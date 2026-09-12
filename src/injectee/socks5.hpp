// Copyright 2022 PragmaTwice
//
// Licensed under the Apache License,
// Version 2.0(the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ENCAPSULE_INJECTEE_SOCKS5
#define ENCAPSULE_INJECTEE_SOCKS5

#include <WinSock2.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <schema.hpp>
#include <string_view>

constexpr const char SOCKS_VERSION = 5;
constexpr const char SOCKS_NO_AUTHENTICATION = 0;

constexpr const char SOCKS_CONNECT = 1;
constexpr const char SOCKS_IPV4 = 1;
constexpr const char SOCKS_DOMAINNAME = 3;
constexpr const char SOCKS_IPV6 = 4;

constexpr const char SOCKS_SUCCESS = 0;
constexpr const char SOCKS_GENERAL_FAILURE = 4;

// RFC 1928 section 4 command, and the section 7 datagram fragment octet.  The
// UDP associate is what turns a socks5 TCP tunnel into a UDP relay; FRAG is 0
// for an unfragmented datagram, which is every one this tool builds.
constexpr const uint8_t SOCKS_UDP_ASSOCIATE = 3;
constexpr const uint8_t SOCKS_FRAG_NOT = 0;

// RFC 1929 username/password subnegotiation, offered as greeting method 2.
constexpr const char SOCKS_USERNAME_PASSWORD = 2;
constexpr const uint8_t SOCKS_AUTH_VERSION = 1;    // the subnegotiation VER
constexpr const uint8_t SOCKS_AUTH_FAILURE = 0xFF;  // the usual rejection code

// A DOMAINNAME request is the widest one the builders below can emit:
// VER + CMD + RSV + ATYP (4) + LEN + name (1 + 255) + PORT (2) == 262.
constexpr const size_t SOCKS_DOMAIN_MAX_LENGTH = 255;
constexpr const size_t SOCKS_REQUEST_MAX_SIZE =
    4 + 1 + SOCKS_DOMAIN_MAX_LENGTH + 2;

// The widest RFC 1928 section 7 datagram header, a DOMAINNAME one:
// RSV (2) + FRAG + ATYP + LEN + name (255) + PORT (2) == 262 -- the same
// size as a DOMAINNAME request, because the two encodings share everything
// from ATYP on.
constexpr const size_t SOCKS_UDP_HEADER_MAX = 4 + 1 + SOCKS_DOMAIN_MAX_LENGTH +
                                              2;

// The widest legal NMETHODS octet (RFC 1928 section 3): a greeting can name
// at most 255 methods.  Named for what it COUNTS -- SOCKS_DOMAIN_MAX_LENGTH is
// 255 too, but by coincidence: that one bounds a domain name's LEN octet, this
// one bounds a method list.  Sharing the old name made a method list look like
// a name, and would silently resize the greeting if either concept ever moved.
// No wire byte changes: the bound is still X'FF' and the buffer still 257.
constexpr const size_t SOCKS_NMETHODS_MAX = 255;

// VER + NMETHODS + up to SOCKS_NMETHODS_MAX methods (RFC 1928 section 3).
constexpr const size_t SOCKS_GREETING_MAX_SIZE = 2 + SOCKS_NMETHODS_MAX;

// VER + ULEN + 255 + PLEN + 255 (RFC 1929).  Note this is 513, not a round
// 512: a caller that sizes its buffer with SOCKS_AUTH_MAX_SIZE must hold the
// widest legal subnegotiation, and 255 + 255 + 3 is 513 bytes.
constexpr const size_t SOCKS_AUTH_MAX_SIZE = 1 + 1 + 255 + 1 + 255;

// ---------------------------------------------------------------- credentials

// A proxy login, borrowed rather than owned: both members are views into
// whatever the caller already holds (an InjectorConfig, a test buffer).  An
// absent credential and an empty one look the same from here, which is fine --
// the P5 contract in schema.hpp says "no authentication" is encoded as ABSENT,
// so nothing (or two empties) means "do not offer method 2".
struct socks5_credentials {
  std::string_view username;
  std::string_view password;

  // True when the config carries at least one credential, i.e. when the
  // greeting should offer RFC 1929.  A username with an empty password stays
  // enabled: some servers really do accept a blank password.
  bool enabled() const {
    return !username.empty() || !password.empty();
  }
};

// Borrow the credentials out of an InjectorConfig (schema.hpp fields 4 and 5,
// the frozen P5 contract).  The views point INTO `cfg`, so `cfg` has to
// outlive the handshake -- at every hook call site it is a local copy that
// does.  Never copies, never allocates: this runs inside a hooked connect().
inline socks5_credentials socks5_credentials_from(const InjectorConfig &cfg) {
  const auto &user = cfg["username"_f];
  const auto &pass = cfg["password"_f];
  return socks5_credentials{user ? *user : std::string_view{},
                            pass ? *pass : std::string_view{}};
}

// ----------------------------------------------------------- pure builders
//
// Everything that only *lays out bytes* is inline, socket-free and heap-free,
// so it is testable on the host (see tests/socks5).  The SOCKET taking
// functions underneath are thin: build the bytes, send them, read the reply.
// RFC 1929 (username/password) was added on top of exactly this seam.

// Writes the client greeting {VER, NMETHODS, METHODS...}.  `methods` holds
// `n` method ids; `out` needs room for `n` + 2 bytes, at most
// SOCKS_GREETING_MAX_SIZE.  Returns the number of bytes written, or 0 when the
// method list is empty or too long to encode -- too long being more than
// SOCKS_NMETHODS_MAX, i.e. more than one NMETHODS octet can spell.
inline size_t socks5_build_greeting(const uint8_t *methods, size_t n,
                                    char *out) {
  if (methods == nullptr || out == nullptr || n == 0 ||
      n > SOCKS_NMETHODS_MAX) {
    return 0;
  }

  out[0] = SOCKS_VERSION;
  out[1] = (char)n;
  for (size_t i = 0; i < n; ++i) {
    out[2 + i] = (char)methods[i];
  }

  return n + 2;
}

// ATYP and the address field that follows it, written from `at` (the octet the
// ATYP goes into): one octet of type, then the address.  Returns the number of
// octets written -- including the ATYP octet -- or 0 for an unknown ATYP, an
// empty or over-long domain, or a null argument.
//
// Shared by the two encoders below on purpose.  A request
// {VER, CMD, RSV, ATYP, ADDR, PORT} and an RFC 1928 section 7 datagram header
// {RSV, RSV, FRAG, ATYP, ADDR, PORT} agree on everything from ATYP onwards,
// so the address rules -- the part with a byte-order trap in it -- are written
// exactly once and cannot drift apart.
inline size_t socks5_write_atyp_addr(uint8_t atyp, const void *addr_bytes,
                                     char *at) {
  if (addr_bytes == nullptr || at == nullptr) {
    return 0;
  }

  const char *src = (const char *)addr_bytes;
  char *addr = at + 1;
  size_t addr_size = 0;

  if (atyp == SOCKS_IPV4) {
    std::memcpy(addr, src, 4);
    addr_size = 4;
  } else if (atyp == SOCKS_IPV6) {
    std::memcpy(addr, src, 16);
    addr_size = 16;
  } else if (atyp == SOCKS_DOMAINNAME) {
    const size_t name_size = std::strlen(src);
    if (name_size == 0 || name_size > SOCKS_DOMAIN_MAX_LENGTH) {
      return 0;
    }
    addr[0] = (char)name_size;
    std::memcpy(addr + 1, src, name_size);
    addr_size = name_size + 1;
  } else {
    return 0;
  }

  at[0] = (char)atyp;
  return addr_size + 1;
}

// PORT, host order in, network order out (most significant octet first) -- the
// other half of what the two encoders share.
inline void socks5_write_port(char *port, uint16_t port_host_order) {
  port[0] = (char)((port_host_order >> 8) & 0xFF);
  port[1] = (char)(port_host_order & 0xFF);
}

// Writes the request {VER, CMD=cmd, RSV=0, ATYP, ADDR, PORT}; `out` needs room
// for SOCKS_REQUEST_MAX_SIZE bytes.
//
// Byte order is the whole point of this function:
//   * `addr_bytes` is copied verbatim and therefore must already carry WIRE
//     (network) order -- 4 octets for SOCKS_IPV4, 16 octets for SOCKS_IPV6;
//   * for SOCKS_DOMAINNAME, `addr_bytes` is a NUL-terminated string of at most
//     SOCKS_DOMAIN_MAX_LENGTH characters, emitted as {LEN, bytes};
//   * `port_host_order` is a plain integer (80, 8080, ...), emitted in network
//     order, most significant octet first.
//
// Returns the number of bytes written, or 0 for an unknown ATYP, an empty or
// over-long domain, or a null argument.  Nothing is written unless the whole
// request can be, so a 0 return leaves `out` as the caller left it.
inline size_t socks5_build_request_cmd(uint8_t cmd, uint8_t atyp,
                                       const void *addr_bytes,
                                       uint16_t port_host_order, char *out) {
  if (out == nullptr) {
    return 0;
  }

  const size_t field = socks5_write_atyp_addr(atyp, addr_bytes, out + 3);
  if (field == 0) {
    return 0;
  }

  out[0] = SOCKS_VERSION;
  out[1] = (char)cmd;
  out[2] = 0;  // RSV
  socks5_write_port(out + 3 + field, port_host_order);

  return field + 5;
}

// The CONNECT request every hook sends today: `socks5_build_request_cmd` with
// the command fixed, kept as the name the call sites and the byte pins use.
inline size_t socks5_build_request(uint8_t atyp, const void *addr_bytes,
                                   uint16_t port_host_order, char *out) {
  return socks5_build_request_cmd(SOCKS_CONNECT, atyp, addr_bytes,
                                  port_host_order, out);
}

// Request bytes for a live `sockaddr` target -- the shape every connect() hook
// hands over.  A sockaddr_in/sockaddr_in6 already holds the address and the
// port in network order, so the octets go through unchanged and the port only
// makes the ntohs -> re-big-endian round trip.  The bytes on the wire are
// exactly what this overload wrote before the refactor.
// Declared ahead of the CONNECT wrapper below, which delegates to it; the
// definition sits past it, next to the ASSOCIATE wrapper it was written for.
// Repeating a declaration costs nothing if that ordering ever changes.
inline size_t socks5_build_request_from_sockaddr_cmd(uint8_t cmd,
                                                     const sockaddr *addr,
                                                     char *out);

inline size_t socks5_build_request_from_sockaddr(const sockaddr *addr,
                                                 char *out) {
  return socks5_build_request_from_sockaddr_cmd(SOCKS_CONNECT, addr, out);
}

// The same, for any RFC 1928 section 4 command: CONNECT (what every connect()
// hook sends) and UDP ASSOCIATE (CMD=3) differ only in that one octet, so the
// family switch below is written once for both.
inline size_t socks5_build_request_from_sockaddr_cmd(uint8_t cmd,
                                                     const sockaddr *addr,
                                                     char *out) {
  if (addr == nullptr) {
    return 0;
  }

  if (addr->sa_family == AF_INET) {
    const auto *v4 = (const sockaddr_in *)addr;
    return socks5_build_request_cmd(cmd, SOCKS_IPV4, &v4->sin_addr,
                                    ntohs(v4->sin_port), out);
  } else if (addr->sa_family == AF_INET6) {
    const auto *v6 = (const sockaddr_in6 *)addr;
    return socks5_build_request_cmd(cmd, SOCKS_IPV6, &v6->sin6_addr,
                                    ntohs(v6->sin6_port), out);
  }

  return 0;  // neither AF_INET nor AF_INET6: caller reports a general failure
}

// The RFC 1928 section 4 UDP ASSOCIATE request for a live `sockaddr` bind hint
// -- CMD=3 and nothing else changes, so the 0.0.0.0:0 hint lays down exactly
// {05 03 00 01 00 00 00 00 00 00}: "relay, pick the address and port you want,
// and tell me in your reply" (tests/socks5 pins both that vector and the
// IPv6/real-port forms).
inline size_t socks5_build_associate_from_sockaddr(const sockaddr *bind_hint,
                                                   char *out) {
  return socks5_build_request_from_sockaddr_cmd(SOCKS_UDP_ASSOCIATE, bind_hint,
                                                out);
}

// Request bytes for an `IpAddr` IPC message.  By schema contract `v4_addr` and
// `port` are HOST order integers (winnet.hpp ntohl/ntohs'ed them, schema.hpp
// from_asio stores host order), while `v6_addr` carries WIRE order octets (what
// from_asio stores, the only producer feeding this overload).  So the v4 octets
// are split most-significant-byte first and the port goes to the builder as a
// host-order integer.  Both used to be dumped raw, which put them on the wire
// REVERSED (reviewer 801436d2); the sockaddr overload was always correct, and
// the two must agree -- tests/socks5 pins that byte for byte.
inline size_t socks5_build_request_from_ip_addr(const IpAddr &addr, char *out) {
  const auto port_field = addr["port"_f];
  if (!port_field) {
    return 0;
  }
  const auto port = (uint16_t)*port_field;

  if (auto v4 = addr["v4_addr"_f]) {
    const auto host_order = *v4;
    const char octets[4] = {(char)((host_order >> 24) & 0xFF),
                            (char)((host_order >> 16) & 0xFF),
                            (char)((host_order >> 8) & 0xFF),
                            (char)(host_order & 0xFF)};
    return socks5_build_request(SOCKS_IPV4, octets, port, out);
  } else if (auto v6 = addr["v6_addr"_f]) {
    if (v6->size() != 16) {
      return 0;
    }
    return socks5_build_request(SOCKS_IPV6, v6->data(), port, out);
  } else if (auto domain = addr["domain"_f]) {
    if (domain->size() > SOCKS_DOMAIN_MAX_LENGTH) {
      return 0;
    }
    char name[SOCKS_DOMAIN_MAX_LENGTH + 1];
    std::copy(domain->begin(), domain->end(), name);
    name[domain->size()] = '\0';
    return socks5_build_request(SOCKS_DOMAINNAME, name, port, out);
  }

  return 0;
}

// Writes the RFC 1929 client subnegotiation
//   {VER=1, ULEN, USERNAME..., PLEN, PASSWORD...}
// into `out`, which needs room for SOCKS_AUTH_MAX_SIZE bytes.  Both lengths fit
// one octet, so a credential longer than 255 bytes cannot be encoded and yields
// 0 (as does a null `out`); the caller reports that as a handshake failure
// rather than truncating a login.  Returns the number of bytes written.
inline size_t socks5_build_auth(std::string_view user, std::string_view pass,
                                uint8_t *out) {
  if (out == nullptr || user.size() > 0xFF || pass.size() > 0xFF) {
    return 0;
  }

  uint8_t *p = out;
  *p++ = SOCKS_AUTH_VERSION;
  *p++ = (uint8_t)user.size();
  for (const char c : user) {
    *p++ = (uint8_t)c;
  }
  *p++ = (uint8_t)pass.size();
  for (const char c : pass) {
    *p++ = (uint8_t)c;
  }

  return (size_t)(p - out);
}

// -------------------------------------------------- UDP datagram header
//
// RFC 1928 section 5 wraps every relayed datagram in
//   {RSV(2)=0, FRAG, ATYP, DST.ADDR, DST.PORT, DATA}
// which is the request layout shifted by one octet: RSV, RSV, FRAG stand
// where VER, CMD, RSV do.  Both encoders below therefore share
// socks5_write_atyp_addr, and a caller can size its buffer with
// SOCKS_UDP_HEADER_MAX for either.

// Builds that header for `atyp`/`addr_bytes`/`port_host_order`, with `frag`
// copied through verbatim (0 = SOCKS_FRAG_NOT, a whole datagram; any other
// value is the caller's fragment number and this builder does not judge it).
// Returns the number of octets written -- 10 for IPv4, 22 for IPv6, 7 + name
// length for a domain -- or 0 for an unknown ATYP, an empty or over-long
// domain, or a null `out`.  On 0 nothing has been written.
inline size_t socks5_build_udp_header(uint8_t atyp, const void *addr_bytes,
                                      uint16_t port_host_order, uint8_t frag,
                                      char *out) {
  if (out == nullptr) {
    return 0;
  }

  const size_t field = socks5_write_atyp_addr(atyp, addr_bytes, out + 3);
  if (field == 0) {
    return 0;
  }

  out[0] = 0;  // RSV
  out[1] = 0;  // RSV
  out[2] = (char)frag;
  socks5_write_port(out + 3 + field, port_host_order);

  return field + 5;
}

// One decoded datagram header.  `addr` carries the WIRE order octets -- the
// first 4 for an IPv4 source, all 16 for IPv6, the name without its LEN octet
// for a domain -- and `port_host_order` has already been brought round to a
// plain integer.  `header_size` is where DATA begins, so the payload is
// [header_size, total).

struct socks5_udp_datagram {
  uint8_t atyp;
  std::array<uint8_t, 16> addr;
  uint16_t port_host_order;
  size_t header_size;
};

// Reads a header a server sent us.  The bytes are hostile by definition --
// they arrive over the relay from wherever the datagram came -- so every field
// is checked against the buffer before it is read, and anything that does not
// describe a whole header yields nullopt rather than a guess:
//   * shorter than the 4 fixed octets, or shorter than the address it claims;
//   * an ATYP that is not IPv4 / IPv6 / DOMAINNAME;
//   * FRAG not zero, because a continuation fragment carries DATA and no
//     address at all, so decoding the octets after ATYP as one would invent
//     a source out of payload bytes;
//   * a domain that is empty, or longer than the 16 octets this struct can
//     carry -- truncating a name would misattribute the datagram, and the
//     capsule resolves names before it associates, so a name this wide is
//     not something the relay path can act on.
// The two RSV octets are NOT checked: they are reserved and ignored, and
// dropping traffic over them would be a policy this decoder has no business
// making.  Nor is anything beyond the header touched.
inline std::optional<socks5_udp_datagram>
socks5_parse_udp_header(const void *data, size_t size) {
  const auto *bytes = (const uint8_t *)data;
  if (bytes == nullptr || size < 4) {
    return std::nullopt;
  }

  if (bytes[2] != SOCKS_FRAG_NOT) {
    return std::nullopt;  // a fragment piece: no address follows ATYP
  }

  const uint8_t atyp = bytes[3];
  size_t addr_at = 4;     // where the address octets start
  size_t addr_size = 0;   // and how many there are

  if (atyp == SOCKS_IPV4) {
    addr_size = 4;
  } else if (atyp == SOCKS_IPV6) {
    addr_size = 16;
  } else if (atyp == SOCKS_DOMAINNAME) {
    if (size < 5) {
      return std::nullopt;
    }
    const size_t name_len = bytes[4];  // the LEN octet in front of the name
    if (name_len == 0 || name_len > 16 || size < 5 + name_len + 2) {
      return std::nullopt;
    }
    addr_at = 5;
    addr_size = name_len;
  } else {
    return std::nullopt;
  }

  const size_t port_at = addr_at + addr_size;
  if (size < port_at + 2) {
    return std::nullopt;
  }

  socks5_udp_datagram out;
  out.atyp = atyp;
  out.addr = {};
  std::memcpy(out.addr.data(), bytes + addr_at, addr_size);
  out.port_host_order = (uint16_t)(((uint16_t)bytes[port_at] << 8) |
                                   (uint16_t)bytes[port_at + 1]);
  out.header_size = port_at + 2;

  return out;
}

// ------------------------------------------------------------ socket layer
//
// NOTE: these define functions at namespace scope WITHOUT `inline`, so this
// header may be included by exactly ONE translation unit per binary.

// What a reply said, as a verdict rather than a bare REP octet.  The connect
// path only ever asked "did it work"; the UDP path has to tell answers apart,
// because a control connection is long-lived and a half-read reply leaves it
// unusable.  There is deliberately no "unknown": nothing may mistake a socket
// whose state we do not understand for one that is still good.
//
//   ok             granted, and the BND decoded
//   refused_rep    the relay said no -- a refused greeting, or REP != X'00'
//   protocol_error what came back is not a reply: a short or missing fixed
//                  header, a VER that is not 5, an ATYP this protocol lacks,
//                  an empty name -- or a socket that could not carry the
//                  request at all
//   truncated      a reply that began legally and was cut inside its own
//                  address: fewer octets than its ATYP demands
//   bnd_is_a_name  a legal reply whose bound address is a NAME.  The text is
//                  kept; the verdict is still a refusal -- socks5_associate
enum class socks5_reply : uint8_t {
  ok,
  refused_rep,
  protocol_error,
  truncated,
  bnd_is_a_name,
};

// BND.ADDR and BND.PORT, as stated by the relay.
struct socks5_relay_endpoint {
  uint8_t atyp = 0;
  uint8_t addr[16] = {};  // WIRE order; the first addr_size octets are real
  size_t addr_size = 0;   // 4, 16, or 0 when the answer was a name
  uint16_t port_host_order = 0;
  char name[SOCKS_DOMAIN_MAX_LENGTH + 1] = {};  // NUL-terminated, atyp 3 only
  size_t name_size = 0;                         // octets, no LEN octet counted

  // A numeric answer also arrives ready for sendto(): AF_INET or AF_INET6,
  // address and port already in it.  A name leaves this AF_UNSPEC.
  sockaddr_storage bound{};
};

// Wipes a frame that held a plaintext login on its way out of scope.
//
// WHY a guard and not a SecureZeroMemory at each `return`: socks5_handshake has
// four exits after the subnegotiation is laid down -- accepted, refused, bad
// version, and socket error -- and a hand-written wipe has to be remembered at
// every one of them, plus at any exit a later edit adds.  Destructors run on
// all of them by construction.  SecureZeroMemory (not memset) because the frame
// is dead stack the moment it runs: an ordinary fill MSVC can prove unread is
// elided, and an elided wipe is the same leak with a comment on it.
struct socks5_auth_frame_scrub {
  uint8_t *frame;
  size_t size;

  ~socks5_auth_frame_scrub() {
    SecureZeroMemory(frame, (DWORD)size);
  }
};

// The RFC 1928 greeting, plus the RFC 1929 subnegotiation when the caller has
// credentials.  creds is REQUIRED, not defaulted: every call site has to say
// where the login comes from, and hook.hpp passes the InjectorConfig it already
// holds.
//
// NOTE -- the frame wiped below is not the only one that held the password,
// and it never was the worst of them.
//
// `creds` borrows: both views point INTO the caller's object, so the octets
// that went out on the wire sit wherever that object sits, for as long as it
// lives.  That is now a bounded statement, because the four connect sites hold
// an injectee_route (client.hpp) instead of a by-value InjectorConfig: it owns
// the login as two fixed arrays, and its destructor SecureZeroMemorys them --
// so the bytes leave with the detour's frame rather than outliving it.  Before
// that, every proxied connect made a fresh unzeroed copy of the whole config,
// one plaintext login per connection, in a process any same-user debugger can
// ReadProcessMemory.
//
// What still holds it, and this function cannot reach any of it:
//   * injectee_config::cfg and ::pinned -- the live config and the fail-closed
//     pin, both std::strings behind mtx, kept for the life of the capsule
//     because routing depends on them.  set() replaces them without wiping
//     what they were.
//   * the InjectorConfig decoded off the IPC stream, which lives in reader()'s
//     lambda frame (client.hpp) until that coroutine ends.  One transient
//     copy per config push rather than one per connect, and not zeroized.
// Anything below either of those has to be scrubbed where it is made, not
// here: nothing this function owns can reach someone else's object.
//
// Any failure returns false and the caller's fail_proxied_connect()
// turns it into WSAECONNREFUSED -- a proxy that refused the login is never
// silently downgraded to an unauthenticated connection.
bool socks5_handshake(SOCKET s, const socks5_credentials &creds) {
  // No credentials: one method, exactly the pre-P5 greeting.  With them: offer
  // username/password FIRST but keep no-auth on the list, so a server with auth
  // disabled can still pick method 0.
  uint8_t methods[2];
  size_t count = 0;
  if (creds.enabled()) {
    methods[count++] = SOCKS_USERNAME_PASSWORD;
    methods[count++] = SOCKS_NO_AUTHENTICATION;
  } else {
    methods[count++] = SOCKS_NO_AUTHENTICATION;
  }

  char req[SOCKS_GREETING_MAX_SIZE];
  const size_t size = socks5_build_greeting(methods, count, req);

  if (size == 0 || send(s, req, (int)size, 0) != (int)size)
    return false;

  char res[2];
  if (recv(s, res, sizeof(res), MSG_WAITALL) != sizeof(res))
    return false;

  if (res[0] != SOCKS_VERSION)
    return false;

  // Method 0: no authentication required -- the outcome P5 left untouched.
  if (res[1] == SOCKS_NO_AUTHENTICATION)
    return true;

  // Method 2 only leads anywhere if we actually offered it.  Everything else,
  // including 0xFF ("no acceptable methods"), fails the handshake.
  if (res[1] != SOCKS_USERNAME_PASSWORD || !creds.enabled())
    return false;

  uint8_t auth[SOCKS_AUTH_MAX_SIZE];
  // Armed before the frame is filled, so it covers the auth_size == 0 case too
  // (nothing was written, so there is nothing to lose -- but the buffer is
  // already in scope and a reader cannot tell a wiped frame from an armed one
  // that was never used).  See socks5_auth_frame_scrub for why this is the
  // wipe that survives the optimizer.
  const socks5_auth_frame_scrub scrub{auth, sizeof(auth)};

  const size_t auth_size =
      socks5_build_auth(creds.username, creds.password, auth);

  if (auth_size == 0 ||
      send(s, (const char *)auth, (int)auth_size, 0) != (int)auth_size)
    return false;

  char auth_res[2];
  if (recv(s, auth_res, sizeof(auth_res), MSG_WAITALL) != sizeof(auth_res))
    return false;

  const auto auth_ver = (uint8_t)auth_res[0];
  const auto auth_status = (uint8_t)auth_res[1];

  // A refused login normally comes back as {1, 0xFF}; any status but 0 is a
  // refusal, whatever the server dressed it in.
  if (auth_status == SOCKS_AUTH_FAILURE)
    return false;

  return auth_ver == SOCKS_AUTH_VERSION && auth_status == SOCKS_SUCCESS;
}

// Read one reply, strictly.  Every part of fixed size is read with
// MSG_WAITALL, so a server that trickles cannot be mistaken for a whole reply,
// and nothing is ever indexed past the octets that actually arrived.  The two
// ways a stream proxy gets out of step with itself are both closed here: a
// short header (the old code read four bytes with no MSG_WAITALL, so one
// arrived and the other three came out of the request buffer -- and a request
// buffer that starts {05 00 00 ...} reads back as "success"), and a reply that
// stops inside its own address (the old code tested only for SOCKET_ERROR, so a
// five-of-six read was a fine tunnel).  The order matters as much as the
// flags: the four fixed octets are read and length-checked BEFORE ATYP is
// believed, because ATYP is what sizes every read after it -- trusting a value
// that arrived in a short read is how a two-octet answer buys a phantom tunnel
// and a follow-on recv that eats the application's own data.  Neither buffer
// is the caller's: the reply lands in `head`, so the request octets a caller
// still holds can never be read back as an answer.  Pinned twice on the
// wire: two_octets_then_close_is_a_protocol_error (the BND path) and
// a_two_octet_reply_never_passes_as_a_tunnel_on_the_connect_path (the connect
// path, where the caller's buffer is the request).
//
// A refusal reads no further.  RFC 1928 fills a failed reply's BND with zeros,
// but a server may close instead, and waiting for six octets that never come
// would hang a blocking socket; leaving them in the stream is what this file
// always did, so the rule stands: a refused control socket is dead.  The pump
// closes its control socket on any verdict but ok anyway.
socks5_reply socks5_read_reply(SOCKET s, uint8_t *rep_out,
                               socks5_relay_endpoint *bnd_out) {
  char head[4];
  if (recv(s, head, 4, MSG_WAITALL) != 4) {
    return socks5_reply::protocol_error;  // short, EOF, or a broken socket
  }
  if (head[0] != SOCKS_VERSION) {
    return socks5_reply::protocol_error;  // whatever answers, it is not SOCKS5
  }

  const auto rep = (uint8_t)head[1];
  if (rep_out != nullptr) {
    *rep_out = rep;
  }
  if (rep != SOCKS_SUCCESS) {
    return socks5_reply::refused_rep;
  }

  const auto atyp = (uint8_t)head[3];
  bool named = false;
  size_t field = 0;  // octets of address, not counting the two of port
  if (atyp == SOCKS_IPV4) {
    field = 4;
  } else if (atyp == SOCKS_IPV6) {
    field = 16;
  } else if (atyp == SOCKS_DOMAINNAME) {
    char len_octet = 0;
    if (recv(s, &len_octet, 1, MSG_WAITALL) != 1) {
      return socks5_reply::protocol_error;
    }
    if ((uint8_t)len_octet == 0) {
      return socks5_reply::protocol_error;  // a name with no bytes, no address
    }
    named = true;
    field = (size_t)(uint8_t)len_octet;  // <= 255 by construction
  } else {
    return socks5_reply::protocol_error;  // an ATYP this protocol does not have
  }

  // The address and its port, in one read, sized by the ATYP that promised
  // them: 257 octets is the widest legal answer and the buffer's size.
  char addr_part[SOCKS_DOMAIN_MAX_LENGTH + 2];
  const size_t need = field + 2;
  if (recv(s, addr_part, (int)need, MSG_WAITALL) != (int)need) {
    return socks5_reply::truncated;  // cut inside its own address
  }

  const uint16_t port =
      (uint16_t)(((uint16_t)(uint8_t)addr_part[field] << 8) |
                 (uint16_t)(uint8_t)addr_part[field + 1]);

  if (bnd_out != nullptr) {
    *bnd_out = socks5_relay_endpoint{};
    bnd_out->atyp = atyp;
    bnd_out->port_host_order = port;
    if (named) {
      bnd_out->name_size = field;
      std::memcpy(bnd_out->name, addr_part, field);
      bnd_out->name[field] = '\0';
      // bound stays AF_UNSPEC: resolving a name the relay handed us would mean
      // a synchronous lookup inside the target process, on the pump's thread,
      // with no proxy to carry it.
    } else {
      bnd_out->addr_size = field;
      std::memcpy(bnd_out->addr, addr_part, field);
      if (atyp == SOCKS_IPV4) {
        auto *v4 = (sockaddr_in *)&bnd_out->bound;
        v4->sin_family = AF_INET;
        std::memcpy(&v4->sin_addr, addr_part, 4);
        v4->sin_port = htons(port);
      } else {
        auto *v6 = (sockaddr_in6 *)&bnd_out->bound;
        v6->sin6_family = AF_INET6;
        std::memcpy(&v6->sin6_addr, addr_part, 16);
        v6->sin6_port = htons(port);
      }
    }
  }

  return named ? socks5_reply::bnd_is_a_name : socks5_reply::ok;
}

// socks5_request_send, with the reply's BND.ADDR / BND.PORT kept: hand over a
// socks5_relay_endpoint to get the relay's address, or nullptr for exactly what
// the connect path wants.  What goes OUT on the wire is the bytes the caller
// built, unchanged; the difference is that the reply is now read to its end or
// not at all, and that a DOMAINNAME BND -- which the connect path cannot use,
// and never could -- is drained and still reported as a general failure.
char socks5_request_ex(SOCKET s, char *buf, size_t size,
                       socks5_relay_endpoint *bnd_out) {
  if (buf == nullptr || size == 0) {
    return SOCKS_GENERAL_FAILURE;
  }
  if (send(s, buf, (int)size, 0) != (int)size) {
    return SOCKS_GENERAL_FAILURE;
  }

  uint8_t rep = (uint8_t)SOCKS_GENERAL_FAILURE;
  const socks5_reply verdict = socks5_read_reply(s, &rep, bnd_out);
  if (verdict == socks5_reply::ok) {
    return SOCKS_SUCCESS;
  }
  if (verdict == socks5_reply::refused_rep) {
    return (char)rep;  // the REP octet, as this function always answered
  }
  return SOCKS_GENERAL_FAILURE;
}

// The four hook.hpp call sites, unchanged: a thin delegate that asks for no
// BND, so the connect path neither sees nor pays for the new code.
char socks5_request_send(SOCKET s, char *buf, size_t size) {
  return socks5_request_ex(s, buf, size, nullptr);
}

char socks5_request(SOCKET s, const sockaddr *addr) {
  char buf[SOCKS_REQUEST_MAX_SIZE];
  const size_t size = socks5_build_request_from_sockaddr(addr, buf);
  if (size == 0)
    return SOCKS_GENERAL_FAILURE;

  return socks5_request_send(s, buf, size);
}

char socks5_request(SOCKET s, const IpAddr &addr) {
  char buf[SOCKS_REQUEST_MAX_SIZE];
  const size_t size = socks5_build_request_from_ip_addr(addr, buf);
  if (size == 0)
    return SOCKS_GENERAL_FAILURE;

  return socks5_request_send(s, buf, size);
}

// UDP ASSOCIATE (RFC 1928 sections 4 and 6) on a control socket: negotiate,
// ask for a relay, and hand back the endpoint the relay assigned.  `control`
// is a TCP socket already connected to the proxy and used for nothing else --
// a relay is granted per connection, so the pump keeps this one open for the
// life of the association and closes it when the association dies.
//
// `creds` are used for the greeting here, exactly as the connect path uses
// them: an authenticated proxy is authenticated before it is asked for a
// relay, and a refused login is never downgraded to an anonymous ASSOCIATE.
// A handshake failure is reported as refused_rep with rep GENERAL_FAILURE:
// whether the method was refused, the login was, or the socket died, the
// answer to "may I have a relay" is no, and the pump's move is the same.
//
// `app_bind_hint` is BND.DST: where the application will send from.  Pass the
// relay socket's own bound address when it is known, or an AF_UNSPEC / zeroed
// sockaddr for "the relay picks" -- which this turns into 0.0.0.0:0 rather
// than failing, because a hooked process that never called bind() genuinely
// does not know yet.
//
// A DOMAINNAME BND is kept as raw text in out_bnd.name and answered
// bnd_is_a_name: it is a legal reply, and this module will not act on it.  The
// relay is telling us to send UDP to a NAME, which in a target process means a
// synchronous, unproxied DNS lookup from the pump thread -- the exact leak this
// capsule exists to prevent.  The pump reports the peer once and closes the
// control socket; it does not resolve, retry, or fall back to direct.
socks5_reply socks5_associate(SOCKET control, const socks5_credentials &creds,
                              const sockaddr &app_bind_hint,
                              socks5_relay_endpoint &out_bnd,
                              uint8_t *rep_out = nullptr) {
  out_bnd = socks5_relay_endpoint{};

  if (!socks5_handshake(control, creds)) {
    if (rep_out != nullptr) {
      *rep_out = (uint8_t)SOCKS_GENERAL_FAILURE;
    }
    return socks5_reply::refused_rep;
  }

  char buf[SOCKS_REQUEST_MAX_SIZE];
  size_t size = socks5_build_associate_from_sockaddr(&app_bind_hint, buf);
  if (size == 0) {
    sockaddr_in any{};
    any.sin_family = AF_INET;  // 0.0.0.0:0: "you pick", the RFC's own wording
    size = socks5_build_associate_from_sockaddr((const sockaddr *)&any, buf);
  }
  if (size == 0 || send(control, buf, (int)size, 0) != (int)size) {
    if (rep_out != nullptr) {
      *rep_out = (uint8_t)SOCKS_GENERAL_FAILURE;
    }
    return socks5_reply::protocol_error;  // the request never reached the relay
  }

  uint8_t rep = (uint8_t)SOCKS_GENERAL_FAILURE;
  const socks5_reply verdict = socks5_read_reply(control, &rep, &out_bnd);
  if (rep_out != nullptr) {
    *rep_out = rep;
  }
  return verdict;
}

#endif  // ENCAPSULE_INJECTEE_SOCKS5

