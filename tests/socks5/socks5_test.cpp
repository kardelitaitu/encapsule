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

// Tests for the pure byte builders in src/injectee/socks5.hpp (ROADMAP P5 seam,
// P2 "tests for socks5 request byte builders").
//
// Nothing here opens a socket: the builders are inline, heap-free and take the
// target as bytes/integers, so the wire format is now a host-side unit test.
//
// NOTE: socks5.hpp defines its SOCKET-taking functions WITHOUT inline, so
// exactly one translation unit per binary may include it.  This file is that TU
// for encapsule_test_socks5.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <WinSock2.h>
#include <Windows.h>

#include <asio/ip/address.hpp>

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace ip = asio::ip;

#include <schema.hpp>
#include <socks5.hpp>

#include "test_support.hpp"

namespace {

using bytes = std::vector<std::uint8_t>;

bytes to_bytes(const char *buf, size_t n) {
  bytes out;
  out.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    out.push_back(static_cast<std::uint8_t>(buf[i]));
  }
  return out;
}

std::string hex(const bytes &v) {
  static const char *digits = "0123456789ABCDEF";
  std::string out;
  for (const auto b : v) {
    if (!out.empty()) {
      out += ' ';
    }
    out += digits[b >> 4];
    out += digits[b & 0xF];
  }
  return out;
}

void check_bytes(const char *expr, const char *file, int line, const char *buf,
                 size_t n, const bytes &want) {
  const bytes got = to_bytes(buf, n);
  if (!(got == want)) {
    ++test_failures;
    std::printf("FAIL %s:%d: %s\n      got  %s\n      want %s\n", file, line,
                expr, hex(got).c_str(), hex(want).c_str());
  }
}

#define CHECK_BYTES(buf, n, want) \
  check_bytes(#buf, __FILE__, __LINE__, (buf), (size_t)(n), (want))

// Same, for a uint8_t buffer (the auth builder deals in uint8_t*).
#define CHECK_BYTES_U8(buf, n, want) \
  CHECK_BYTES((const char *)(buf), n, want)

// 203.0.113.7 (TEST-NET-3) and 2001:db8::1 (documentation range) -- the two
// addresses pinned by the expectations below.
constexpr std::uint32_t k203_0_113_7_host_order = 0xCB007107u;
constexpr std::array<unsigned char, 16> k2001db8_1_wire{
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

sockaddr_in make_v4(std::uint32_t host_order_addr, std::uint16_t port) {
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(host_order_addr);
  sa.sin_port = htons(port);
  return sa;
}

sockaddr_in6 make_v6(const std::array<unsigned char, 16> &wire,
                     std::uint16_t port) {
  sockaddr_in6 sa{};
  sa.sin6_family = AF_INET6;
  std::memcpy(&sa.sin6_addr, wire.data(), wire.size());
  sa.sin6_port = htons(port);
  return sa;
}

const sockaddr *as_sockaddr(const sockaddr_in *sa) {
  return (const sockaddr *)sa;
}
const sockaddr *as_sockaddr(const sockaddr_in6 *sa) {
  return (const sockaddr *)sa;
}

// The vectors this suite exists to pin.
const bytes kGreetingNoAuth{0x05, 0x01, 0x00};
// Credentials in play: RFC 1929 (method 2) offered FIRST, no-auth kept on the
// list so a server with auth disabled can still answer 0.
const bytes kGreetingUserpassFirst{0x05, 0x02, 0x02, 0x00};
const bytes kAuthRequest{0x01, 0x05, 0x61, 0x6c, 0x69, 0x63, 0x65,  // 1 alice
                         0x07, 0x73, 0x33, 0x63, 0x72, 0x33, 0x74,
                         0x21};  // s3cr3t!  -- VER ULEN U PLEN P, 15 bytes
const bytes kRequestV4{0x05, 0x01, 0x00, 0x01, 0xCB, 0x00, 0x71,
                       0x07, 0x1F, 0x90};  // 203.0.113.7:8080
// 22 bytes: VER CMD RSV ATYP + 16 address octets + PORT.
const bytes kRequestV6{0x05, 0x01, 0x00, 0x04,        // VER CMD RSV ATYP=4
                       0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                       0x11, 0x51};                    // [2001:db8::1]:4433
// 18 bytes: 4 header + LEN(1) + 11 name octets + port.
const bytes kRequestDomain{0x05, 0x01, 0x00, 0x03, 0x0b, 'e', 'x', 'a', 'm',
                           'p', 'l', 'e',  '.',  'c',  'o', 'm', 0x00, 0x50};

// ---------------------------------------------------------------- P7 / UDP
//
// The two shapes RFC 1928 adds for datagrams: an ASSOCIATE request (section 4
// CMD=3) asking the relay for a port, and the section 5/7 header in front of
// every datagram that port then carries.  Same addresses as above, so a reader
// can see the two encodings side by side.

// VER CMD=3 RSV ATYP=1 then a 0.0.0.0:0 bind address: "any address, any port"
// -- the client does not know its relay endpoint yet and asks the server to
// assign one, which is what the reply then reports back.
const bytes kUdpAssociateAny{0x05, 0x03, 0x00, 0x01, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00};
// RSV(2) FRAG ATYP, then the address at the SAME offset it has in a request.
const bytes kUdpHeaderV4{0x00, 0x00, 0x00, 0x01, 0xCB, 0x00, 0x71,
                         0x07, 0x1F, 0x90};  // from 203.0.113.7:8080
const bytes kUdpHeaderV6{0x00, 0x00, 0x00, 0x04,        // RSV RSV FRAG ATYP=4
                         0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                         0x11, 0x51};                    // [2001:db8::1]:4433
// 18 bytes: 4 fixed + LEN(1) + 11 name octets + PORT.
const bytes kUdpHeaderDomain{0x00, 0x00, 0x00, 0x03, 0x0b, 'e', 'x', 'a',
                             'm', 'p', 'l',  'e',  '.',  'c', 'o', 'm',
                             0x00, 0x50};

}  // namespace

// ------------------------------------------------------------------ greeting

void build_greeting_offers_no_auth() {
  char buf[SOCKS_GREETING_MAX_SIZE] = {};
  const uint8_t methods[] = {SOCKS_NO_AUTHENTICATION};

  const size_t n = socks5_build_greeting(methods, sizeof(methods), buf);
  CHECK_EQ(n, 3u);
  CHECK_BYTES(buf, n, kGreetingNoAuth);
}

void build_greeting_offers_userpass_then_no_auth() {
  // What socks5_handshake sends with credentials configured (P5 #2).
  char buf[SOCKS_GREETING_MAX_SIZE] = {};
  const uint8_t methods[] = {SOCKS_USERNAME_PASSWORD, SOCKS_NO_AUTHENTICATION};

  const size_t n = socks5_build_greeting(methods, sizeof(methods), buf);
  CHECK_EQ(n, 4u);
  CHECK_BYTES(buf, n, kGreetingUserpassFirst);
}

void build_greeting_rejects_unencodable_method_lists() {
  char buf[SOCKS_GREETING_MAX_SIZE] = {};
  const uint8_t methods[256] = {};

  CHECK_EQ(socks5_build_greeting(methods, 0, buf), 0u);
  CHECK_EQ(socks5_build_greeting(methods, 256, buf), 0u);
  CHECK_EQ(socks5_build_greeting(nullptr, 1, buf), 0u);
  CHECK_EQ(socks5_build_greeting(methods, 1, nullptr), 0u);
  CHECK_EQ(socks5_build_greeting(methods, 255, buf), 257u);  // fits exactly
}

// ------------------------------------------------------------------- request

void build_request_ipv4_is_network_order() {
  char buf[SOCKS_REQUEST_MAX_SIZE] = {};
  const uint8_t octets[] = {203, 0, 113, 7};

  const size_t n = socks5_build_request(SOCKS_IPV4, octets, 8080, buf);
  CHECK_EQ(n, 10u);
  CHECK_BYTES(buf, n, kRequestV4);
}

void build_request_ipv6() {
  char buf[SOCKS_REQUEST_MAX_SIZE] = {};

  const size_t n =
      socks5_build_request(SOCKS_IPV6, k2001db8_1_wire.data(), 4433, buf);
  CHECK_EQ(n, 22u);
  CHECK_EQ(kRequestV6.size(), 22u);
  CHECK_BYTES(buf, n, kRequestV6);
}

void build_request_domain() {
  char buf[SOCKS_REQUEST_MAX_SIZE] = {};
  const char name[] = "example.com";

  const size_t n = socks5_build_request(SOCKS_DOMAINNAME, name, 80, buf);
  CHECK_EQ(n, 18u);
  CHECK_EQ(kRequestDomain.size(), 18u);
  CHECK_BYTES(buf, n, kRequestDomain);
}

void build_request_rejects_bad_input() {
  char buf[SOCKS_REQUEST_MAX_SIZE] = {};
  const uint8_t octets[] = {203, 0, 113, 7};
  char name[257];
  std::memset(name, 'a', 256);  // 256 characters: one past the LEN limit
  name[256] = '\0';

  CHECK_EQ(socks5_build_request(0x02, octets, 80, buf), 0u);   // no BIND
  CHECK_EQ(socks5_build_request(0x09, octets, 80, buf), 0u);   // unknown ATYP
  CHECK_EQ(socks5_build_request(SOCKS_IPV4, nullptr, 80, buf), 0u);
  CHECK_EQ(socks5_build_request(SOCKS_DOMAINNAME, "", 80, buf), 0u);
  CHECK_EQ(socks5_build_request(SOCKS_DOMAINNAME, name, 80, buf), 0u);
}

void build_request_longest_domain_fits_the_buffer() {
  // A 255-octet label is the widest legal request: 4 + 1 + 255 + 2 == 262,
  // which is exactly SOCKS_REQUEST_MAX_SIZE.  The buffer used to be 134, so
  // this request overran it.
  char name[256];
  for (size_t i = 0; i < 255; ++i) {
    name[i] = (char)('a' + (int)(i % 26));
  }
  name[255] = '\0';

  char buf[SOCKS_REQUEST_MAX_SIZE] = {};
  const size_t n = socks5_build_request(SOCKS_DOMAINNAME, name, 65535, buf);

  CHECK_EQ(n, SOCKS_REQUEST_MAX_SIZE);
  CHECK_EQ(buf[3], SOCKS_DOMAINNAME);
  CHECK_EQ((std::uint8_t)buf[4], 255u);
  CHECK_EQ((std::uint8_t)buf[260], 0xFFu);  // port 65535, big endian
  CHECK_EQ((std::uint8_t)buf[261], 0xFFu);
}

// ------------------------------------------------------- live sockaddr input
//
// The connect() hooks pass the target sockaddr straight through, and a
// sockaddr already carries network-order octets and a network-order port.
// These pins are what the injected DLL put on the wire before the refactor;
// they must not move.

void request_from_sockaddr_ipv4_is_unchanged() {
  const auto sa = make_v4(k203_0_113_7_host_order, 8080);
  char buf[SOCKS_REQUEST_MAX_SIZE] = {};

  const size_t n = socks5_build_request_from_sockaddr(as_sockaddr(&sa), buf);
  CHECK_EQ(n, 10u);
  CHECK_BYTES(buf, n, kRequestV4);
}

void request_from_sockaddr_ipv6_is_unchanged() {
  const auto sa = make_v6(k2001db8_1_wire, 4433);
  char buf[SOCKS_REQUEST_MAX_SIZE] = {};

  const size_t n = socks5_build_request_from_sockaddr(as_sockaddr(&sa), buf);
  CHECK_EQ(n, 22u);
  CHECK_BYTES(buf, n, kRequestV6);
}

void request_from_sockaddr_rejects_other_families() {
  sockaddr unspec{};
  unspec.sa_family = AF_UNSPEC;
  char buf[SOCKS_REQUEST_MAX_SIZE] = {};

  CHECK_EQ(socks5_build_request_from_sockaddr(&unspec, buf), 0u);
  CHECK_EQ(socks5_build_request_from_sockaddr(nullptr, buf), 0u);
}

// ---------------------------------------------------------- IpAddr overload
//
// ipaddr_from_name (hook.hpp) builds the IpAddr the other overload receives,
// through schema.hpp from_asio: v4_addr and port are HOST order integers and
// v6_addr holds WIRE order octets.  For the same target both overloads must
// emit the same bytes; that identity is the bug fix (reviewer 801436d2), where
// the IpAddr path used to write the v4 uint32 and the port raw, i.e. reversed.
// (winnet.hpp to_ip_addr stores v6 reversed -- that is P4 #1's open byte-order
// question, and to_ip_addr never reaches socks5_request.)

void request_from_ip_addr_ipv4_needs_network_order() {
  const IpAddr msg = from_asio(ip::make_address("203.0.113.7"), 8080);
  char buf[SOCKS_REQUEST_MAX_SIZE] = {};

  const size_t n = socks5_build_request_from_ip_addr(msg, buf);
  CHECK_EQ(n, 10u);
  CHECK_BYTES(buf, n, kRequestV4);
}

void request_from_ip_addr_ipv6() {
  const IpAddr msg = from_asio(ip::make_address("2001:db8::1"), 4433);
  char buf[SOCKS_REQUEST_MAX_SIZE] = {};

  const size_t n = socks5_build_request_from_ip_addr(msg, buf);
  CHECK_EQ(n, 22u);
  CHECK_BYTES(buf, n, kRequestV6);
}

void request_from_ip_addr_domain() {
  const IpAddr msg{{}, {}, std::string("example.com"), 80u};
  char buf[SOCKS_REQUEST_MAX_SIZE] = {};

  const size_t n = socks5_build_request_from_ip_addr(msg, buf);
  CHECK_EQ(n, 18u);
  CHECK_BYTES(buf, n, kRequestDomain);
}

void request_from_ip_addr_rejects_unusable_messages() {
  char buf[SOCKS_REQUEST_MAX_SIZE] = {};

  const IpAddr no_port{0x08080808u, {}, {}, {}};
  CHECK_EQ(socks5_build_request_from_ip_addr(no_port, buf), 0u);

  const IpAddr short_v6{{}, std::vector<unsigned char>(15, 0), {}, 443u};
  CHECK_EQ(socks5_build_request_from_ip_addr(short_v6, buf), 0u);

  const IpAddr empty_domain{{}, {}, std::string(), 443u};
  CHECK_EQ(socks5_build_request_from_ip_addr(empty_domain, buf), 0u);

  const IpAddr long_domain{{}, {}, std::string(256, 'a'), 443u};
  CHECK_EQ(socks5_build_request_from_ip_addr(long_domain, buf), 0u);
}

void overloads_agree_byte_for_byte_ipv4() {
  const auto sa = make_v4(k203_0_113_7_host_order, 8080);
  const IpAddr msg = from_asio(ip::make_address("203.0.113.7"), 8080);

  char via_sockaddr[SOCKS_REQUEST_MAX_SIZE] = {};
  char via_ip_addr[SOCKS_REQUEST_MAX_SIZE] = {};
  const size_t a =
      socks5_build_request_from_sockaddr(as_sockaddr(&sa), via_sockaddr);
  const size_t b = socks5_build_request_from_ip_addr(msg, via_ip_addr);

  CHECK_EQ(a, b);
  CHECK(std::memcmp(via_sockaddr, via_ip_addr, a) == 0);
  CHECK_BYTES(via_ip_addr, b, to_bytes(via_sockaddr, a));
}

void overloads_agree_byte_for_byte_ipv6() {
  const auto sa = make_v6(k2001db8_1_wire, 4433);
  const IpAddr msg = from_asio(ip::make_address("2001:db8::1"), 4433);

  char via_sockaddr[SOCKS_REQUEST_MAX_SIZE] = {};
  char via_ip_addr[SOCKS_REQUEST_MAX_SIZE] = {};
  const size_t a =
      socks5_build_request_from_sockaddr(as_sockaddr(&sa), via_sockaddr);
  const size_t b = socks5_build_request_from_ip_addr(msg, via_ip_addr);

  CHECK_EQ(a, b);
  CHECK(a == 22u);
  CHECK(std::memcmp(via_sockaddr, via_ip_addr, a) == 0);
}

// --------------------------------------------------------------------- UDP
//
// The pure half of RFC 1928 sections 4 (CMD=3), 5 and 7: what an ASSOCIATE
// request looks like, what heads a relayed datagram, and what comes back when
// a server hands one to us.  Still no sockets -- and the parser is written for
// bytes nobody can trust, because a datagram header arrives from the network.

void udp_constants_match_the_contract() {
  CHECK_EQ((int)SOCKS_UDP_ASSOCIATE, 3);  // the section 4 command id
  CHECK_EQ((int)SOCKS_FRAG_NOT, 0);       // an unfragmented datagram
  // RSV(2) + FRAG + ATYP + LEN + name + PORT, i.e. as wide as a request.
  CHECK_EQ(SOCKS_UDP_HEADER_MAX, 262u);
  CHECK_EQ(SOCKS_UDP_HEADER_MAX, SOCKS_REQUEST_MAX_SIZE);
}

// The generalization that let ASSOCIATE be built: socks5_build_request now
// delegates, and the CONNECT bytes every hook puts on the wire must not have
// moved by one bit.  These are the pre-existing pins, rebuilt through the
// command-taking form.
void build_request_cmd_keeps_the_connect_pins() {
  char buf[SOCKS_REQUEST_MAX_SIZE] = {};
  const uint8_t octets[] = {203, 0, 113, 7};
  const char name[] = "example.com";

  CHECK_EQ(socks5_build_request_cmd(SOCKS_CONNECT, SOCKS_IPV4, octets, 8080,
                                    buf),
           10u);
  CHECK_BYTES(buf, 10, kRequestV4);

  std::memset(buf, 0, sizeof(buf));
  CHECK_EQ(socks5_build_request_cmd(SOCKS_CONNECT, SOCKS_IPV6,
                                    k2001db8_1_wire.data(), 4433, buf),
           22u);
  CHECK_BYTES(buf, 22, kRequestV6);

  std::memset(buf, 0, sizeof(buf));
  CHECK_EQ(socks5_build_request_cmd(SOCKS_CONNECT, SOCKS_DOMAINNAME, name, 80,
                                    buf),
           18u);
  CHECK_BYTES(buf, 18, kRequestDomain);

  // ... and the delegating form still agrees with it.
  char via_cmd[SOCKS_REQUEST_MAX_SIZE] = {};
  char via_connect[SOCKS_REQUEST_MAX_SIZE] = {};
  const size_t a = socks5_build_request_cmd(SOCKS_CONNECT, SOCKS_IPV4, octets,
                                           8080, via_cmd);
  const size_t b =
      socks5_build_request(SOCKS_IPV4, octets, 8080, via_connect);
  CHECK_EQ(a, b);
  CHECK(std::memcmp(via_cmd, via_connect, a) == 0);
}

void udp_associate_asks_for_a_relay_assigned_endpoint() {
  // 0.0.0.0:0 in the BND.ADDR / BND.PORT fields: the client has no preference
  // and lets the relay pick, which is how a hooked process that never called
  // bind() still gets a port.  The only difference from a CONNECT request is
  // the CMD octet -- everything from ATYP on is the same encoding.
  char buf[SOCKS_REQUEST_MAX_SIZE] = {};
  const uint8_t any[4] = {0, 0, 0, 0};

  const size_t n =
      socks5_build_request_cmd(SOCKS_UDP_ASSOCIATE, SOCKS_IPV4, any, 0, buf);
  CHECK_EQ(n, 10u);
  CHECK_BYTES(buf, n, kUdpAssociateAny);
  CHECK_EQ((int)buf[1], (int)SOCKS_UDP_ASSOCIATE);

  char connect_buf[SOCKS_REQUEST_MAX_SIZE] = {};
  const size_t c = socks5_build_request(SOCKS_IPV4, any, 0, connect_buf);
  CHECK_EQ(c, n);
  // RSV + ATYP + ADDR + PORT are the same encoding in both; only CMD
  // differs, which is the next two checks.
  CHECK_EQ(std::memcmp(buf + 2, connect_buf + 2, n - 2), 0);
  CHECK_EQ((int)connect_buf[1], (int)SOCKS_CONNECT);
  CHECK_EQ((int)buf[2], 0);  // RSV, in both
}

void build_udp_header_ipv4_is_network_order() {
  char buf[SOCKS_UDP_HEADER_MAX] = {};
  const uint8_t octets[] = {203, 0, 113, 7};

  const size_t n =
      socks5_build_udp_header(SOCKS_IPV4, octets, 8080, SOCKS_FRAG_NOT, buf);
  CHECK_EQ(n, 10u);
  CHECK_BYTES(buf, n, kUdpHeaderV4);
  CHECK_EQ((int)buf[0], 0);  // RSV
  CHECK_EQ((int)buf[1], 0);  // RSV
  CHECK_EQ((int)buf[2], (int)SOCKS_FRAG_NOT);
}

void build_udp_header_ipv6_and_domain() {
  char buf[SOCKS_UDP_HEADER_MAX] = {};

  const size_t v6 = socks5_build_udp_header(SOCKS_IPV6, k2001db8_1_wire.data(),
                                            4433, SOCKS_FRAG_NOT, buf);
  CHECK_EQ(v6, 22u);
  CHECK_BYTES(buf, v6, kUdpHeaderV6);

  std::memset(buf, 0, sizeof(buf));
  const char name[] = "example.com";
  const size_t dn =
      socks5_build_udp_header(SOCKS_DOMAINNAME, name, 80, SOCKS_FRAG_NOT, buf);
  CHECK_EQ(dn, 18u);
  CHECK_EQ(kUdpHeaderDomain.size(), 18u);
  CHECK_BYTES(buf, dn, kUdpHeaderDomain);

  // 5 + LEN + 2 for a domain: the LEN octet is counted once, not twice.
  CHECK_EQ(dn, 5u + std::strlen(name) + 2u);
}

void build_udp_header_passes_the_fragment_octet_through() {
  // FRAG is the caller's business: an unfragmented datagram is 0, and any
  // other value is a continuation number this builder only copies.  The
  // parser underneath refuses those, so the pair is deliberate.
  char buf[SOCKS_UDP_HEADER_MAX] = {};
  const uint8_t octets[] = {203, 0, 113, 7};
  const uint8_t frags[] = {0x01, 0x02, 0x0f, 0x7f, 0xff};

  for (const uint8_t frag : frags) {
    std::memset(buf, 0, sizeof(buf));
    const size_t n = socks5_build_udp_header(SOCKS_IPV4, octets, 8080,
                                                 frag, buf);
    CHECK_EQ(n, 10u);
    CHECK_EQ((int)(std::uint8_t)buf[2], (int)frag);
    // everything else is the unfragmented pin
    CHECK_EQ(std::memcmp(buf, kUdpHeaderV4.data(), 2), 0);
    CHECK_EQ(std::memcmp(buf + 3, kUdpHeaderV4.data() + 3, 7), 0);
  }
}

void build_udp_header_rejects_bad_input() {
  char buf[SOCKS_UDP_HEADER_MAX] = {};
  const uint8_t octets[] = {203, 0, 113, 7};
  char name[257];
  std::memset(name, 'a', 256);
  name[256] = '\0';

  CHECK_EQ(socks5_build_udp_header(0x02, octets, 80, 0, buf), 0u);
  CHECK_EQ(socks5_build_udp_header(0x09, octets, 80, 0, buf), 0u);
  CHECK_EQ(socks5_build_udp_header(SOCKS_IPV4, nullptr, 80, 0, buf), 0u);
  CHECK_EQ(socks5_build_udp_header(SOCKS_DOMAINNAME, "", 80, 0, buf), 0u);
  CHECK_EQ(socks5_build_udp_header(SOCKS_DOMAINNAME, name, 80, 0, buf), 0u);
  CHECK_EQ(socks5_build_udp_header(SOCKS_IPV4, octets, 80, 0, nullptr), 0u);

  // 255 octets is the limit, and it lands exactly in SOCKS_UDP_HEADER_MAX.
  char longest[SOCKS_DOMAIN_MAX_LENGTH + 1];
  std::memset(longest, 'b', SOCKS_DOMAIN_MAX_LENGTH);
  longest[SOCKS_DOMAIN_MAX_LENGTH] = '\0';
  CHECK_EQ(socks5_build_udp_header(SOCKS_DOMAINNAME, longest, 1, 0, buf),
           SOCKS_UDP_HEADER_MAX);
}

void parse_udp_header_round_trips_every_form() {
  struct case_v {
    uint8_t atyp;
    const void *addr;
    size_t addr_size;
    uint16_t port;
  };
  const uint8_t v4_octets[] = {203, 0, 113, 7};
  const char name[] = "example.com";
  const case_v cases[] = {
      {SOCKS_IPV4, v4_octets, 4, 8080},
      {SOCKS_IPV6, k2001db8_1_wire.data(), 16, 4433},
      {SOCKS_DOMAINNAME, name, 11, 80},
  };

  for (const auto &c : cases) {
    char datagram[SOCKS_UDP_HEADER_MAX + 6] = {};
    const size_t n = socks5_build_udp_header(c.atyp, c.addr, c.port,
                                             SOCKS_FRAG_NOT, datagram);
    CHECK(n > 0);
    std::memcpy(datagram + n, "hello", 5);  // the payload the header fronts

    const auto parsed =
        socks5_parse_udp_header(datagram, n + 5 /* header + payload */);
    CHECK(parsed.has_value());
    if (!parsed) {
      continue;
    }
    CHECK_EQ((int)parsed->atyp, (int)c.atyp);
    CHECK_EQ(parsed->port_host_order, c.port);
    CHECK_EQ(parsed->header_size, n);
    CHECK(std::memcmp(parsed->addr.data(), c.addr, c.addr_size) == 0);
    // an IPv4 address fills the low 4 octets, the rest stays zeroed
    for (size_t i = c.atyp == SOCKS_IPV4 ? 4 : c.addr_size; i < 16; ++i) {
      CHECK_EQ((int)parsed->addr[i], 0);
    }
    // DATA starts at header_size, not before
    CHECK_EQ(std::memcmp(datagram + parsed->header_size, "hello", 5), 0);
  }
}

void parse_udp_header_rejects_hostile_bytes() {
  char buf[SOCKS_UDP_HEADER_MAX] = {};
  const uint8_t octets[] = {203, 0, 113, 7};
  const char name[] = "example.com";
  const size_t v4 =
      socks5_build_udp_header(SOCKS_IPV4, octets, 8080, SOCKS_FRAG_NOT, buf);
  CHECK_EQ(v4, 10u);

  CHECK(!socks5_parse_udp_header(nullptr, 0).has_value());
  CHECK(!socks5_parse_udp_header(buf, 0).has_value());
  // every truncation of a whole header, down to nothing
  for (size_t n = 1; n < v4; ++n) {
    CHECK(!socks5_parse_udp_header(buf, n).has_value());
  }
  // the whole header plus its payload still parses (no size == header rule)
  std::memcpy(buf + v4, "hello", 5);
  CHECK(socks5_parse_udp_header(buf, v4 + 5).has_value());

  // an ATYP that is not one of the three, including one with no reply
  char bogus[SOCKS_UDP_HEADER_MAX] = {};
  std::memcpy(bogus, buf, v4);
  for (const uint8_t atyp : {(uint8_t)0x00, (uint8_t)0x02, (uint8_t)0x05,
                             (uint8_t)0xFF}) {
    bogus[3] = (char)atyp;
    CHECK(!socks5_parse_udp_header(bogus, v4).has_value());
  }

  // a fragment continuation: DATA follows FRAG, so the address is not there to
  // be read -- decoding those octets anyway would invent a source
  char frag[SOCKS_UDP_HEADER_MAX] = {};
  std::memcpy(frag, buf, v4);
  frag[2] = 1;
  CHECK(!socks5_parse_udp_header(frag, v4).has_value());

  // a domain header whose LEN claims more than the buffer holds
  char dn[SOCKS_UDP_HEADER_MAX] = {};
  const size_t d = socks5_build_udp_header(SOCKS_DOMAINNAME, name, 80, 0, dn);
  CHECK_EQ(d, 18u);
  for (size_t n = 1; n < d; ++n) {
    CHECK(!socks5_parse_udp_header(dn, n).has_value());
  }
  CHECK(socks5_parse_udp_header(dn, d).has_value());

  char oversized[SOCKS_UDP_HEADER_MAX] = {};
  std::memcpy(oversized, dn, d);
  oversized[4] = (char)0xFF;  // 255 octets of name in an 18 octet datagram
  CHECK(!socks5_parse_udp_header(oversized, d).has_value());

  // ... and a name too wide for the struct that would have to carry it: a
  // truncated source address is worse than no source address
  char wide[SOCKS_UDP_HEADER_MAX] = {};
  char long_name[32];
  std::memset(long_name, 'c', 31);
  long_name[31] = '\0';
  const size_t w =
      socks5_build_udp_header(SOCKS_DOMAINNAME, long_name, 80, 0, wide);
  CHECK_EQ(w, 38u);
  CHECK(!socks5_parse_udp_header(wide, w).has_value());

  // a LEN of 0 is not an address either
  char empty_name[SOCKS_UDP_HEADER_MAX] = {};
  std::memcpy(empty_name, dn, d);
  empty_name[4] = 0;
  CHECK(!socks5_parse_udp_header(empty_name, d).has_value());
}

// ---------------------------------------------------------------- RFC 1929
//
// socks5_build_auth lays out the subnegotiation request; socks5_handshake is
// the state machine around it (greeting -> server choice -> auth -> status).
// Only the bytes are host-testable -- the state machine needs a live proxy, so
// the accept/refuse walks belong to the e2e auth test (P5 S6).

namespace {

// The greeting socks5_handshake() emits for a given credential state, spelled
// out with the same method order the handshake uses.
bytes handshake_greeting_for(const socks5_credentials &creds) {
  uint8_t methods[2];
  size_t count = 0;
  if (creds.enabled()) {
    methods[count++] = SOCKS_USERNAME_PASSWORD;
    methods[count++] = SOCKS_NO_AUTHENTICATION;
  } else {
    methods[count++] = SOCKS_NO_AUTHENTICATION;
  }

  char buf[SOCKS_GREETING_MAX_SIZE] = {};
  return to_bytes(buf, socks5_build_greeting(methods, count, buf));
}

}  // namespace

void auth_constants_match_the_contract() {
  CHECK_EQ((int)SOCKS_USERNAME_PASSWORD, 2);   // greeting method id
  CHECK_EQ((int)SOCKS_AUTH_VERSION, 1);        // subnegotiation VER
  CHECK_EQ((int)SOCKS_AUTH_FAILURE, 0xFF);     // the usual rejection status
  CHECK_EQ(SOCKS_AUTH_MAX_SIZE, 513u);         // 1 + 1 + 255 + 1 + 255
}

void build_auth_pins_the_request_bytes() {
  uint8_t buf[SOCKS_AUTH_MAX_SIZE] = {};

  const size_t n = socks5_build_auth("alice", "s3cr3t!", buf);
  CHECK_EQ(n, 15u);
  CHECK_EQ(kAuthRequest.size(), 15u);
  CHECK_BYTES_U8(buf, n, kAuthRequest);
}

void build_auth_takes_the_255_octet_boundary() {
  const std::string user(255, 'u');
  const std::string pass(255, 'p');
  uint8_t buf[SOCKS_AUTH_MAX_SIZE] = {};

  const size_t n = socks5_build_auth(user, pass, buf);
  CHECK_EQ(n, SOCKS_AUTH_MAX_SIZE);  // the widest legal login fills it exactly
  CHECK_EQ((int)buf[0], (int)SOCKS_AUTH_VERSION);
  CHECK_EQ((int)buf[1], 255);            // ULEN
  CHECK_EQ((int)buf[2], (int)'u');       // first username octet
  CHECK_EQ((int)buf[256], (int)'u');     // the 255th
  CHECK_EQ((int)buf[257], 255);          // PLEN sits right behind it
  CHECK_EQ((int)buf[258], (int)'p');
  CHECK_EQ((int)buf[512], (int)'p');
}

void build_auth_rejects_what_one_length_octet_cannot_hold() {
  const std::string ok(255, 'u');
  const std::string too_long(256, 'u');
  uint8_t buf[SOCKS_AUTH_MAX_SIZE] = {};

  CHECK_EQ(socks5_build_auth(too_long, ok, buf), 0u);
  CHECK_EQ(socks5_build_auth(ok, too_long, buf), 0u);
  CHECK_EQ(socks5_build_auth(too_long, too_long, buf), 0u);
  CHECK_EQ(socks5_build_auth(ok, ok, nullptr), 0u);
  // one octet shorter on each side still fits, and reports its real length
  CHECK_EQ(socks5_build_auth(ok, ok.substr(0, 254), buf), 512u);
}

void build_auth_encodes_empty_credential_fields() {
  // A zero-length field is legal 1929; whether the server takes it is its own
  // business.  Deciding whether to offer method 2 at all is enabled()'s job.
  uint8_t buf[SOCKS_AUTH_MAX_SIZE] = {};
  const bytes want{0x01, 0x00, 0x00};

  const size_t n = socks5_build_auth("", "", buf);
  CHECK_EQ(n, 3u);
  CHECK_BYTES_U8(buf, n, want);
}

void credentials_are_views_with_enablement_semantics() {
  // Views only, no storage: what the caller handed over is what it holds.
  const socks5_credentials none;
  const socks5_credentials both{"alice", "s3cr3t!"};
  const socks5_credentials user_only{"alice", ""};
  const socks5_credentials pass_only{"", "pw"};

  CHECK(!none.enabled());
  CHECK(both.enabled());
  CHECK(user_only.enabled());   // a blank password is still a credential
  CHECK(pass_only.enabled());

  CHECK_EQ(both.username, std::string_view("alice"));
  CHECK_EQ(both.password, std::string_view("s3cr3t!"));
  CHECK(user_only.password.empty());
  CHECK(pass_only.username.empty());
}

void credentials_borrowed_from_the_injector_config() {
  InjectorConfig cfg{IpAddr{{}, {}, std::string("proxy.example.com"), 1080u},
                     true, false, {}, {}};
  // schema.hpp fields 4/5 absent => no auth offered, the P5 contract.
  CHECK(!socks5_credentials_from(cfg).enabled());

  cfg["username"_f] = std::string("alice");
  cfg["password"_f] = std::string("s3cr3t!");
  const socks5_credentials creds = socks5_credentials_from(cfg);
  CHECK(creds.enabled());
  CHECK_EQ(creds.username, std::string_view("alice"));
  CHECK_EQ(creds.password, std::string_view("s3cr3t!"));
  // views into the config the caller keeps alive -- nothing was copied
  CHECK_EQ(creds.username.data(), cfg["username"_f]->data());

  // Username only (a genuinely blank password) is still an offer to auth.
  const InjectorConfig user_only{IpAddr{0x0A000001u, {}, {}, 1080u}, {}, {},
                                 std::string("anon"), {}};
  const auto partial = socks5_credentials_from(user_only);
  CHECK(partial.enabled());
  CHECK_EQ(partial.username, std::string_view("anon"));
  CHECK(partial.password.empty());
}

void handshake_offer_tracks_the_credential_state() {
  CHECK_EQ(handshake_greeting_for(socks5_credentials{}), kGreetingNoAuth);
  CHECK_EQ(handshake_greeting_for(socks5_credentials{"alice", "pw"}),
           kGreetingUserpassFirst);

  // The two greetings are the only shapes the injectee can send, and the
  // credential-free one is byte-for-byte what it sent before P5.
  CHECK(handshake_greeting_for(socks5_credentials{}) == kGreetingNoAuth);
}

// ------------------------------------------------------------------- output

void print_pinned_vectors() {
  std::printf("\npinned wire bytes:\n");
  std::printf("  greeting no-auth        %s\n", hex(kGreetingNoAuth).c_str());
  std::printf("  greeting userpass-first %s\n",
              hex(kGreetingUserpassFirst).c_str());
  std::printf("  auth   alice/s3cr3t!    %s\n", hex(kAuthRequest).c_str());
  std::printf("  v4   203.0.113.7:8080   %s\n", hex(kRequestV4).c_str());
  std::printf("  v6   [2001:db8::1]:4433 %s\n", hex(kRequestV6).c_str());
  std::printf("  domain example.com:80   %s\n", hex(kRequestDomain).c_str());
  std::printf("  udp associate 0.0.0.0:0 %s\n", hex(kUdpAssociateAny).c_str());
  std::printf("  udp hdr v4 203.0.113.7   %s\n", hex(kUdpHeaderV4).c_str());
  std::printf("  udp hdr v6 [2001:db8::1] %s\n", hex(kUdpHeaderV6).c_str());
  std::printf("  udp hdr example.com:80   %s\n", hex(kUdpHeaderDomain).c_str());
}

int main() {
  WSADATA wsa{};
  const int err = WSAStartup(MAKEWORD(2, 2), &wsa);
  if (err != 0) {
    std::printf("FAIL WSAStartup: %d\n", err);
    return 1;
  }

  RUN(build_greeting_offers_no_auth);
  RUN(build_greeting_offers_userpass_then_no_auth);
  RUN(build_greeting_rejects_unencodable_method_lists);
  RUN(build_request_ipv4_is_network_order);
  RUN(build_request_ipv6);
  RUN(build_request_domain);
  RUN(build_request_rejects_bad_input);
  RUN(build_request_longest_domain_fits_the_buffer);
  RUN(request_from_sockaddr_ipv4_is_unchanged);
  RUN(request_from_sockaddr_ipv6_is_unchanged);
  RUN(request_from_sockaddr_rejects_other_families);
  RUN(request_from_ip_addr_ipv4_needs_network_order);
  RUN(request_from_ip_addr_ipv6);
  RUN(request_from_ip_addr_domain);
  RUN(request_from_ip_addr_rejects_unusable_messages);
  RUN(overloads_agree_byte_for_byte_ipv4);
  RUN(overloads_agree_byte_for_byte_ipv6);
  RUN(auth_constants_match_the_contract);
  RUN(build_auth_pins_the_request_bytes);
  RUN(build_auth_takes_the_255_octet_boundary);
  RUN(build_auth_rejects_what_one_length_octet_cannot_hold);
  RUN(build_auth_encodes_empty_credential_fields);
  RUN(credentials_are_views_with_enablement_semantics);
  RUN(credentials_borrowed_from_the_injector_config);
  RUN(handshake_offer_tracks_the_credential_state);
  RUN(udp_constants_match_the_contract);
  RUN(build_request_cmd_keeps_the_connect_pins);
  RUN(udp_associate_asks_for_a_relay_assigned_endpoint);
  RUN(build_udp_header_ipv4_is_network_order);
  RUN(build_udp_header_ipv6_and_domain);
  RUN(build_udp_header_passes_the_fragment_octet_through);
  RUN(build_udp_header_rejects_bad_input);
  RUN(parse_udp_header_round_trips_every_form);
  RUN(parse_udp_header_rejects_hostile_bytes);

  print_pinned_vectors();

  WSACleanup();
  return test_failures;
}

