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

// The sockaddr half of the fake-IP design (ROADMAP P6a S1): recognise a
// fabricated address on its way out of a victim process, and turn it, together
// with the table's answer, into the three-way decision a connect site makes.
//
// PURE AND HOST-TESTABLE.  No winsock function is called anywhere in here:
// <winsock2.h> is included for the address LAYOUTS only (sockaddr,
// sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t), which is what lets a
// test hand this layer a byte buffer on the stack and never open a socket --
// the same deal tests/fakeip and tests/udp have with their headers.  No global,
// no lock, no allocation, no thread assumption, no config: the table's answer
// and the "is a proxy configured" flag arrive as PARAMETERS, because
// load_scope(), the stream-classification gate and the table's owner belong to
// the caller (S3 wires it).  Everything is inline or constexpr, so unlike
// socks5.hpp there is no single-TU trap -- any number of translation units in
// one binary may include this header.
//
// WHY IT READS THE OCTETS ITSELF (the V6 TRAP, ROADMAP P6).  winnet.hpp's
// to_ip_addr STORES a v6 address REVERSED while to_asio and
// socks5_build_request_from_ip_addr read it in WIRE ORDER -- a difference
// pinned by tests/winnet, and P4-1's to fix.  This layer never calls to_ip_addr
// and never produces an IpAddr.  It reads four octets out of the buffer in wire
// order and hands back a NAME, because a recovered name is precisely the DOMAIN
// IpAddr the connect sites want (ATYP=3 on the wire), and a DOMAIN is the only
// spelling the fake path may ever produce.  So P6 is immune to that
// inconsistency instead of depending on it being repaired, and a native
// (non-mapped) v6 answer is not recognised at all -- see read_fake_addr.
//
// WHY THE LENGTH GUARDS ARE THE POINT.  Every function here runs inside a
// VICTIM process, on a sockaddr that process allocated.  A caller advertising
// fewer bytes than a struct needs is not exotic: connect() and friends take an
// explicit length, and a driver that passes 8 with AF_INET has told the truth
// about an 8-byte buffer.  Reading sin_addr anyway is an out-of-bounds read in
// somebody else's address space -- it faults the target, or it leaks whatever
// sat past the end as an "address".  So the answer for a buffer we cannot read
// is the answer for an unmatched one: not a fake, run the original call.

#ifndef ENCAPSULE_INJECTEE_FAKE_MAP
#define ENCAPSULE_INJECTEE_FAKE_MAP

// The layouts this header reads are declared only from that floor up, and they
// are split across three SDK headers -- winsock2.h alone gives sockaddr and
// sockaddr_in, sockaddr_in6 lives in ws2ipdef.h and socklen_t in ws2tcpip.h --
// so a TU reaching here with an older (or unset) _WIN32_WINNT would fail with a
// wall of "undeclared identifier" instead of this one line.  The injectee is
// built at 0x0A00 (CMakeLists.txt:81,99); this header wants no more than that,
// and it wants none of the three headers' FUNCTIONS.
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600
#error "fake_map.hpp needs _WIN32_WINNT >= 0x0600 for the sockaddr layouts"
#endif

#include <winsock2.h>  // sockaddr, sockaddr_in
#include <ws2ipdef.h>  // sockaddr_in6 (winsock2.h does not pull this one in)
#include <ws2tcpip.h>  // socklen_t, typedef'd nowhere else in the SDK

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "fakeip.hpp"  // the range, the slot arithmetic, the name a fake holds

// ------------------------------------------------- the buffer bounds we honour

// The least we may read: sa_family is the first two bytes of every address
// family, so below this the buffer does not even say who it is.  Guarding the
// read rather than assuming a sockaddr's 16 bytes is the whole difference
// between this layer and a bare "name->sa_family" on a buffer of unknown size.
inline constexpr socklen_t FAKE_MAP_FAMILY_BYTES =
    static_cast<socklen_t>(sizeof(std::uint16_t));

// The most we believe.  A caller is allowed to pass the size of the STORAGE it
// used rather than the size of the address inside it -- sizeof
// (sockaddr_storage) for a v4 connect happens in real code -- and treating that
// as "not one of ours" would send a fake straight to the TEST-NET-2 blackhole,
// which is the one outcome this design exists to prevent.  Past the storage
// there is no Windows address shape left to describe, so a bigger length is a
// caller that is not talking about an address at all.
inline constexpr socklen_t FAKE_MAP_MAX_LENGTH =
    static_cast<socklen_t>(sizeof(sockaddr_storage));

// The layouts the reader depends on: these are compile-time facts about the
// SDK headers, and they are asserted rather than assumed because every offset
// below is derived from them.
static_assert(sizeof(sockaddr) == 16);
static_assert(sizeof(sockaddr_in) == 16);
static_assert(sizeof(sockaddr_in6) == 28);
static_assert(sizeof(sockaddr_storage) == 128);

// ------------------------------------------------------------------- reading

// What a sockaddr buffer told us, and how much of it we were willing to read.
// Plain data, no handle, no allocation: safe to copy into a local beside the
// arguments of the original call.
struct fake_addr_read {
  // The address bytes were inside the advertised length, so "v4", "slot" and
  // "port" below mean what they say.  False for a short buffer, an unknown
  // family, or a native v6 -- nothing was read past the bytes the caller
  // promised.
  bool readable = false;
  // TEST-NET-2 in either spelling, .0 and .255 included.  This is the
  // membership question, and the one the refusal policy turns on: an address in
  // the range is never a real host, so it must never be routed direct.
  bool in_range = false;
  // In the range AND on a host byte the table could have issued, i.e.
  // fake_ip_slot_of() has an answer.  This is "a fake address we would have
  // issued"; .0 and .255 sit in_range without ever being issuable.
  bool issuable = false;
  std::array<std::uint8_t, 4> v4{};  // meaningful when in_range
  std::size_t slot = 0;              // meaningful when issuable
  std::uint16_t port = 0;            // host order; meaningful when readable
};

// The two octets of a sin_port / sin6_port, in wire order, as a host value.
// Written out as shifts instead of ntohs() so this header calls no winsock API
// and stays testable with nothing on the link line.
inline constexpr std::uint16_t fake_map_host_port(const std::uint8_t *bytes) {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(bytes[0]) << 8) |
      static_cast<std::uint16_t>(bytes[1]));
}

// The RFC 4291 v4-mapped shape: ten zero bytes, ff ff, then the v4 address.
// "bytes" is the 16-byte address blob of a sockaddr_in6, already proven to sit
// inside the caller's length.
inline constexpr bool fake_map_is_v4_mapped(const std::uint8_t *bytes) {
  for (std::size_t i = 0; i < 10; ++i) {
    if (bytes[i] != 0) {
      return false;
    }
  }
  return bytes[10] == 0xff && bytes[11] == 0xff;
}

namespace fake_map_detail {

// The tail both families share: ask the table's own range predicates about the
// octets, so TEST-NET-2 is defined in exactly one place (fakeip.hpp) and this
// layer cannot drift away from the range that hands the addresses out.
inline void fake_map_classify(fake_addr_read &out) {
  out.in_range = in_fake_range(out.v4);
  if (const auto slot = fake_ip_slot_of(out.v4)) {
    out.issuable = true;
    out.slot = *slot;
  }
}

}  // namespace fake_map_detail

// The recognizer.  AF_INET and the ::ffff:198.51.100.x spelling of the same
// answer are decoded; nothing else is.
//
// Deliberately NOT a verdict: it says only what the bytes are.  The caller
// takes "v4" to the table (under its own lock), then brings the answer back to
// fake_connect_verdict().  Keeping those apart is what makes the lock order
// visible at the call site instead of hidden inside a helper.
inline fake_addr_read read_fake_addr(const sockaddr *name, socklen_t len) {
  fake_addr_read out;

  // Length first, family second: reading sa_family is itself a read, and
  // socklen_t is signed, so a negative length is hostile input rather than a
  // very large one.  The upper bound is the storage ceiling above.
  if (name == nullptr || len < FAKE_MAP_FAMILY_BYTES ||
      len > FAKE_MAP_MAX_LENGTH) {
    return out;  // nothing read at all
  }

  if (name->sa_family == AF_INET) {
    if (len < static_cast<socklen_t>(sizeof(sockaddr_in))) {
      return out;  // an AF_INET buffer that cannot hold an address
    }
    const auto *v4 = reinterpret_cast<const sockaddr_in *>(name);
    // Reading the address through unsigned char is the representation-level
    // access the standard allows, and it is endian-independent by construction:
    // these ARE the octets, in the order the wire uses, with no ntohl() to get
    // the direction of a shift wrong.
    const auto *addr = reinterpret_cast<const std::uint8_t *>(&v4->sin_addr);
    const auto *port = reinterpret_cast<const std::uint8_t *>(&v4->sin_port);

    out.readable = true;
    out.v4 = {addr[0], addr[1], addr[2], addr[3]};
    out.port = fake_map_host_port(port);
    fake_map_detail::fake_map_classify(out);
    return out;
  }

  if (name->sa_family == AF_INET6) {
    if (len < static_cast<socklen_t>(sizeof(sockaddr_in6))) {
      return out;  // cannot see the whole 16-byte blob, cannot claim anything
    }
    const auto *v6 = reinterpret_cast<const sockaddr_in6 *>(name);
    const auto *addr = reinterpret_cast<const std::uint8_t *>(&v6->sin6_addr);
    const auto *port = reinterpret_cast<const std::uint8_t *>(&v6->sin6_port);

    // Only the mapped spelling of a fake is a fake.  A native v6 answer came
    // from a real resolver -- the fake path never emits one (the V6 TRAP) -- so
    // there is no row to recover and no business claiming it.
    if (!fake_map_is_v4_mapped(addr)) {
      return out;
    }

    out.readable = true;
    out.v4 = {addr[12], addr[13], addr[14], addr[15]};
    out.port = fake_map_host_port(port);
    fake_map_detail::fake_map_classify(out);
    return out;
  }

  return out;  // AF_UNIX, AF_UNSPEC, AF_BTH, garbage: not an internet address
}

// Two questions worth asking before a caller takes the table's lock, in the
// order it asks them: "is this one of ours at all", and "could the table have
// issued it".  Both are one pass over the guards above, so neither is a cheaper
// path -- they are the readable spelling of a single read.
inline bool addr_in_fake_range(const sockaddr *name, socklen_t len) {
  return read_fake_addr(name, len).in_range;
}

inline bool is_fake_ip_addr(const sockaddr *name, socklen_t len) {
  return read_fake_addr(name, len).issuable;
}

// ------------------------------------------------------------------ verdicts

// The three things a connect site can do with an address, per the accepted
// policy.  The names are spelled for the call sites, not for the enum's
// convenience:
//   route_by_name  re-issue the connect as a socks5 ATYP=3 DOMAIN request for
//                  "name", against the proxy, with the original port.
//   refuse         fail the connect (fail_proxied_connect / WSAECONNREFUSED).
//                  Never a quiet direct route to an address in the range.
//   passthrough    run the original call, untouched.
enum class fake_verdict { route_by_name, refuse, passthrough };

// For a log line or a report: fixed text, no allocation.
inline constexpr std::string_view fake_verdict_text(fake_verdict v) {
  switch (v) {
    case fake_verdict::route_by_name:
      return "route_by_name";
    case fake_verdict::refuse:
      return "refuse";
    case fake_verdict::passthrough:
      return "passthrough";
  }
  return "unreachable";
}

// The table's answer, passed IN.  The caller owns the table, the lock and the
// string; this is a borrowed view of it, which is how the layer stays free of
// allocation.  A fake_table_answer therefore lives no longer than the
// std::optional<std::string> (or table row) it was made from, so the intended
// shape is one lookup and one decision inside the same lock scope.
struct fake_table_answer {
  bool found = false;
  std::string_view name;

  static constexpr fake_table_answer miss() { return {}; }

  // A row the caller fetched itself, without an optional in sight.
  static constexpr fake_table_answer borrowed(std::string_view name) {
    return {true, name};
  }

  // Exactly what fake_ip_table::lookup() returns.  nullopt is a miss, and a row
  // holding an empty name is a miss too: the table cannot own an empty name,
  // and routing to "" is routing to nowhere.
  static fake_table_answer from_lookup(const std::optional<std::string> &row) {
    if (!row || row->empty()) {
      return {};
    }
    return {true, std::string_view(*row)};
  }
};

// The decision, with everything a call site needs to act without reading the
// sockaddr again: the verdict, the name to put on the wire, and the octets/slot
// to pin or unpin when the connection ends.
struct fake_connect_decision {
  fake_verdict verdict = fake_verdict::passthrough;
  std::string_view name;  // borrowed; non-empty ONLY for route_by_name
  fake_addr_read addr;    // what the sockaddr said, whatever the verdict
};

// The policy, as a pure function of the two facts the caller brings.  Four
// rules, in this order, and the order is the design:
//
//  1. Not in the range -- including a buffer too short to read -- is not ours:
//     passthrough, whatever the table was told and whatever the config says.  A
//     real destination must never be captured by a stale row.
//  2. In the range WITH a name behind it is the normal case: route by that
//     name, never by the address, and never as a v6 IpAddr.
//  3. In the range WITHOUT one is the nameless-fake case: a fake whose row was
//     never issued, was evicted, was excluded as the proxy's own address, or is
//     simply .0/.255.  With a proxy that connect refuses -- direct would be a
//     documented-range blackhole and a doctrine violation, and the refusal
//     costs nothing because that connect fails either way.  With no proxy there
//     is nothing to route through, so the original call runs, exactly as the
//     "unknown" stream-classification branch does.
//  4. Nothing here reads config, a table, a clock or thread-local state, so the
//     same arguments always give the same verdict, from any thread.
inline fake_connect_decision fake_connect_verdict(
    const fake_addr_read &addr, const fake_table_answer &answer,
    bool proxy_configured) {
  fake_connect_decision out;
  out.addr = addr;

  if (!addr.in_range) {
    out.verdict = fake_verdict::passthrough;
    return out;
  }

  if (answer.found && !answer.name.empty()) {
    out.verdict = fake_verdict::route_by_name;
    out.name = answer.name;
    return out;
  }

  out.verdict =
      proxy_configured ? fake_verdict::refuse : fake_verdict::passthrough;
  return out;
}

// The same decision starting from the buffer, for a call site that has the
// sockaddr and a row in hand and wants one line.  It re-reads the address
// rather than caching anything, so it costs one pass over 4 or 16 bytes.
inline fake_connect_decision fake_connect_verdict(
    const sockaddr *name, socklen_t len, const fake_table_answer &answer,
    bool proxy_configured) {
  return fake_connect_verdict(read_fake_addr(name, len), answer,
                             proxy_configured);
}

// For the call sites that already hold the octets -- the resolve side knows the
// fake it is about to hand out, and a test knows the one it built by hand:
// spell octets as the reader's answer, so a verdict can be asked without a
// buffer at all.  Same classification path as read_fake_addr, so the two can
// never disagree about what is in range.
inline fake_addr_read fake_addr_read_of(const std::array<std::uint8_t, 4> &v4,
                                        std::uint16_t port) {
  fake_addr_read out;
  out.readable = true;
  out.v4 = v4;
  out.port = port;
  fake_map_detail::fake_map_classify(out);
  return out;
}

#endif  // ENCAPSULE_INJECTEE_FAKE_MAP
