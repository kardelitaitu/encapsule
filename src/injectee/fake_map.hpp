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

// The sockaddr half of the fake-IP design (ROADMAP P6a S1 + S2): recognise a
// fabricated address on its way out of a victim process, turn it, together with
// the table's answer, into the three-way decision a connect site makes, and own
// the one table those decisions are taken against.
//
// PURE AND HOST-TESTABLE.  No winsock function is called anywhere in here:
// <winsock2.h> is included for the address LAYOUTS only (sockaddr,
// sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t), which is what lets a
// test hand this layer a byte buffer on the stack and never open a socket --
// the same deal tests/fakeip and tests/udp have with their headers.  The
// recognizer (read_fake_addr) and the policy (fake_connect_verdict) are pure
// functions of their arguments: no global, no lock, no allocation, no thread
// assumption, no config -- the table's answer and the "is a proxy configured"
// flag arrive as PARAMETERS, because load_scope(), the stream-classification
// gate and the do-not-fake name rules belong to the caller (S3 wires them).
// fake_ip_owner (S2) is the one class here that holds a mutex, and it is the
// only thing that touches a table.  Every function in this header is inline or
// constexpr, so unlike socks5.hpp there is no single-TU trap: any number of
// translation units in one binary may include it, and they all share the one
// owner.
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
#include <mutex>
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

// The same decision for a caller that is about to CROSS A LOCK RELEASE -- i.e.
// the owner's decide().  The name is a std::string, because an answer taken
// under the table's mutex has to outlive that mutex: the next alloc() can
// retire, clear, re-claim or destroy the row a view pointed at, and by then the
// lock is gone and nothing can stop it.  So this is the shape S3 hands to
// socks5_request: an owned name, a port and an address that is not used.
struct fake_owned_decision {
  fake_verdict verdict = fake_verdict::passthrough;
  std::string name;  // OWNED; non-empty ONLY for route_by_name
  fake_addr_read addr;
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

// --------------------------------------------------------------- the owner

// One fake_ip_table, one mutex, one accessor.  This is the whole of P6a S2:
// the piece that decides WHERE the table lives and WHO may hold it, so that S3
// can wire the connect sites without inventing a fourth global.
//
// WHY A FUNCTION STATIC AND NOT A GLOBAL (the C4 lesson, stated in full).  The
// three scope-bound globals hook.hpp reads -- queue, config, nbio_map -- are
// POINTERS that do_client() publishes and retires through scope_ptr_bind, so
// one thread swaps them while another is inside a detour.  That is what forced
// every read through load_scope(), and it is what made the startup window a
// real state a detour can observe: null, or the previous run's object.  A
// fake_ip_table cannot be spelled that way.  It is 254 rows plus two clocks,
// non-copyable, non-rebindable, so the only thing to publish is its ADDRESS,
// and an address that never changes is not a hazard -- it is a fact.  So the
// object is a function-local static behind an inline accessor:
//
//   * residency by construction -- the first call to instance() builds it, and
//     nothing can un-build it.  There is no window in which the table is
//     missing, therefore no null check, no acquire, no "not yet configured".
//   * the injectee is resident by design (it is never unloaded, no FreeLibrary
//     path exists), so the object is never retired while a victim thread could
//     still be inside a detour.  The C4 problem was a live object being taken
//     away; this one cannot be taken away.
//   * the accessor is defined inside the class body, hence implicitly inline,
//     and a local static in an inline function is ONE object for the whole
//     binary ([basic.stc.static]) -- not one per translation unit.  That is
//     the difference from a static file-scope object, and it is why no TU
//     gets a private table that quietly disagrees with the shared one.
//   * std::mutex has no copy, no rebind and no "swap in a new proxy", so the
//     lock a row is claimed under is the same lock it is retired under for
//     the life of the process.
//
// WHAT THE LOCK IS AND IS NOT ALLOWED TO COVER.  Every method here takes
// mutex_ once, with a lock_guard, and calls straight into fake_ip_table.  The
// one rule that keeps that true is that NO CALL IS EVER MADE INTO THIS CLASS
// WHILE ITS MUTEX IS HELD: where an overload delegates (the sockaddr forms, the
// uint32 exclusion), the delegation happens BEFORE the lock is taken -- the
// recognizer and the policy are pure, so the buffer can be decoded outside the
// critical section and handed in.  std::mutex is not recursive, so a
// re-entrant call would be a deadlock rather than an error message, and a
// deadlock inside a victim's connect detour is the worst failure this DLL can
// produce; that is why the rule is stated here, why every delegating overload
// is annotated, and which invariant the S2 mutation test exists to prove.
//
// Nothing in a critical section touches a socket, an event, a file, a
// registry key or the injector: the whole of it is 254-row scans, byte
// copies and the two address predicates.  It is NOT allocation
// free and the comment in fakeip.hpp is the reason -- a row name is a
// std::string, so alloc() assigns one and lookup() copies one, and either can
// throw std::bad_alloc.  That is the honest shape: the only thing that can
// block a holder of this mutex is a malloc that has to grow the heap, on a
// row that is a dozen bytes.  A detour must not let bad_alloc escape into the
// victim, so S3 catches it around these calls and fails the connect closed;
// the lock_guard means the mutex is released on that unwinding either way.
//
// WHAT COMES BACK IS OWNED, NEVER BORROWED.  lookup() hands back a
// std::optional<std::string> and decide() a std::string, both copies.  A
// string_view into a row is a view into memory that the NEXT alloc() can
// retire, clear, re-claim for another name, or destroy -- and the caller has
// already dropped the lock by then, so the table cannot stop it.  That is the
// same class of bug the quarantine ring exists to prevent, moved from the
// network to the address space.  S1's fake_connect_decision still carries a
// view, because it is built from a caller-supplied row inside one expression;
// the owner's decide() is the one that crosses a lock release, so it copies.
//
// WHAT IS DELIBERATELY NOT HERE.  No config, no load_scope(), no proxy
// endpoint, no socket type, no no_fake_name() gate: whether a proxy is
// configured and whether a name may be faked at all are the caller's
// decisions, made before it reaches this class, and proxy_configured arrives
// as a parameter.  Keeping them out is what lets the owner be built before
// any configuration exists -- which is exactly the startup window the dossier
// refuses to black-hole.
class fake_ip_owner {
public:
  // The same type as fake_addr_read::v4 and fake_ip_table::octets: four octets
  // in wire order.  Named here so the signatures below fit the column.
  using octets = fake_ip_table::octets;

  // A test builds its own owner with its own ring length; production uses
  // instance().  The default quarantine is fakeip.hpp's, not a second number
  // to keep in sync.
  explicit fake_ip_owner(
      std::size_t quarantine = FAKEIP_DEFAULT_QUARANTINE)
      : table_(octets{}, quarantine) {}

  fake_ip_owner(const fake_ip_owner &) = delete;
  fake_ip_owner &operator=(const fake_ip_owner &) = delete;

  // THE accessor.  One object per binary, alive from the first call to
  // process exit.  Nothing else in the DLL needs to know it exists.
  static fake_ip_owner &instance() {
    static fake_ip_owner owner;
    return owner;
  }

  // The fake for a name, or nullopt when the table has nothing to give (every
  // slot pinned, or the ring draining).  The answer is a fake_addr_read, i.e.
  // the same shape read_fake_addr produces for a buffer, so the resolve side
  // and the connect side hand each other one type and cannot disagree about
  // whether it is in range.  The port stays 0: a fake carries no port, the
  // caller keeps the one it was given.
  //
  // Not gated by no_fake_name() -- see WHAT IS DELIBERATELY NOT HERE.
  std::optional<fake_addr_read> alloc_for(std::string_view name) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto issued = table_.alloc(name);
    if (!issued) {
      return std::nullopt;
    }
    return fake_addr_read_of(*issued, 0);
  }

  // The name a fake was issued for, as a COPY, or nullopt for "never issued",
  // "already retired" and "not one of ours" alike.  This is the call the
  // connect sites make; the returned optional owns its bytes, so the caller
  // can drop the lock, build a socks5 request, and still have the name.
  std::optional<std::string> lookup(const octets &fake) {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.lookup(fake);
  }

  // The same question from the buffer a connect site was handed.  The
  // recognizer decides what to ask the table for, so a native v6 or a short
  // buffer is answered without a lookup at all.
  std::optional<std::string> lookup(const sockaddr *name, socklen_t len) {
    const auto addr = read_fake_addr(name, len);  // pure: no lock needed
    if (!addr.in_range) {
      return std::nullopt;
    }
    return lookup(addr.v4);
  }

  // In flight bookkeeping.  Both are false for an address the table does not
  // currently hold, and unpin never underflows (fakeip.hpp owns that rule).
  bool pin(const octets &fake) {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.pin(fake);
  }

  bool unpin(const octets &fake) {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.unpin(fake);
  }

  std::size_t pins(const octets &fake) {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.pins(fake);
  }

  // Keep a name at the top of the LRU because a connection using it is still
  // alive.  False when there is no row to warm.
  bool note_touched(const octets &fake) {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.note_touched(fake);
  }

  bool note_touched(const sockaddr *name, socklen_t len) {
    const auto addr = read_fake_addr(name, len);  // pure: no lock needed
    if (!addr.in_range) {
      return false;
    }
    return note_touched(addr.v4);
  }

  // The tick the pump and the connect path advance.  Not a std::function, not
  // a clock read, not a thread: the caller says "time passed" and how much, and
  // the ring moves by that many allocations.  Returns the new clock value.
  std::uint64_t forward_progress(std::size_t ticks = 1) {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.note_progress(ticks);
  }

  // The runtime exclusion, so the front-end path that sets an endpoint calls
  // one thing.  Both spellings are the same address: the octets form, and the
  // uint32 an IpAddr carries (fakeip.hpp's fake_ip_from_u32 decodes it, so a
  // caller holding parse_proxy_url's answer needs no bit_cast and no ntohl).
  // Additive and idempotent; if the address was mapped, the row is RETIRED
  // here -- the fail-closed direction fakeip.hpp argues for, and the reason a
  // proxy moving into the range cannot leave a live loop behind.
  void exclude_proxy(const octets &fake) {
    std::lock_guard<std::mutex> lock(mutex_);
    table_.exclude(fake);
  }

  void exclude_proxy(std::uint32_t v4_value) {
    exclude_proxy(fake_ip_from_u32(v4_value));  // pure, and never re-locks
  }

  bool excludes(const octets &fake) {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.excluded(fake);
  }

  // The counters a report line wants, all under the same lock as the rows.
  std::size_t live_names() {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.live_names();
  }

  std::size_t quarantined() {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.quarantined();
  }

  std::size_t exclusions() {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.exclusions();
  }

  std::size_t capacity() {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.capacity();
  }

  std::size_t quarantine() {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.quarantine();
  }

  // THE CONNECT SITES' ONE CALL: recognise the buffer, ask the table, apply
  // the S1 policy, and hand back an OWNED name.  proxy_configured is the
  // caller's -- it is read from load_scope() outside this lock, which is what
  // keeps the two locks (this mutex and the config's own) from ever nesting.
  fake_owned_decision decide(const fake_addr_read &addr,
                             bool proxy_configured) {
    fake_owned_decision out;
    out.addr = addr;

    // Cheap and lock-free first: most connects are to addresses that are not
    // ours, and taking a mutex for one of those would serialise the whole
    // process behind traffic this table has no opinion about.
    if (!addr.in_range) {
      out.verdict = fake_verdict::passthrough;
      return out;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto row = table_.lookup(addr.v4);
    const auto pure = fake_connect_verdict(
        addr, fake_table_answer::from_lookup(row), proxy_configured);
    out.verdict = pure.verdict;
    if (pure.verdict == fake_verdict::route_by_name && row) {
      out.name = *row;  // the copy that makes this safe to return
    }
    return out;
  }

  fake_owned_decision decide(const sockaddr *name, socklen_t len,
                             bool proxy_configured) {
    // The recognizer is pure, so read it before the lock and pass the result
    // in; this keeps the critical section to one lookup and one copy.
    return decide(read_fake_addr(name, len), proxy_configured);
  }

private:
  fake_ip_table table_;
  // Guards table_ and nothing else.  Declared after it so the destruction
  // order (mutex first, table second) is the one a static teardown wants.
  std::mutex mutex_;
};

#endif  // ENCAPSULE_INJECTEE_FAKE_MAP
