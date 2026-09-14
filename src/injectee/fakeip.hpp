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

// Fake-IP name table (ROADMAP P6a T1 + T2): the bookkeeping half of resolving a
// hostname to a fabricated address and back again.
//
// NOT A SOCKET LAYER.  Nothing here takes or returns a winsock type, reads a
// byte off the wire, or mentions schema.hpp: the table speaks octet arrays and
// names, which is why tests/fakeip can unit-test all of it on the host with no
// target process and no proxy at all.  T3 is the layer that feeds it real
// sockaddr/IpAddr values and owns the lock.
//
// Unlike socks5.hpp, EVERYTHING below is inline or constexpr, so there is no
// single-TU trap: any number of translation units in one binary may include
// this header.  What it does not do is hide a table inside itself -- one
// fake_ip_table is one namespace of names, so its single owner (T3 will make it
// a DLL global) has to be chosen outside.

#ifndef ENCAPSULE_INJECTEE_FAKEIP
#define ENCAPSULE_INJECTEE_FAKEIP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

// ------------------------------------------------------------ the range (T1)

// TEST-NET-2, RFC 5737: reserved for documentation, guaranteed not to route,
// which is the property a fake has to have.  A fabricated address that a real
// host could own is a way to deliver somebody else's traffic.
inline constexpr std::array<std::uint8_t, 4> FAKEIP_RANGE{198, 51, 100, 0};

// .0 is the network and .255 the broadcast, so .1 through .254 is the whole
// table: 254 names at a time, with no growth, no allocation and no failure
// path beyond "the table has nothing to give".
inline constexpr std::size_t FAKEIP_FIRST_HOST = 1;
inline constexpr std::size_t FAKEIP_CAPACITY = 256 - FAKEIP_FIRST_HOST - 1;

// How long an evicted slot waits before another name may have it, counted in
// allocations.  Half the range by default: an application, or a DNS cache in
// front of it, can hold on to a name's answer for a long time, and handing that
// address to a different name early silently routes one host's sessions to the
// other.  Waiting costs slots; a misroute costs the design.
inline constexpr std::size_t FAKEIP_DEFAULT_QUARANTINE = FAKEIP_CAPACITY / 2;

// Membership in the /24, .0 and .255 included.  The question is "is this one of
// ours", not "could the table have issued it": an address in the range that was
// never handed out still has to be recognised as belonging to the table, so it
// fails as unknown instead of being treated as a real destination.
inline constexpr bool in_fake_range(const std::array<std::uint8_t, 4> &v4) {
  return v4[0] == FAKEIP_RANGE[0] && v4[1] == FAKEIP_RANGE[1] &&
         v4[2] == FAKEIP_RANGE[2];
}

// The slot-th address of the range, host byte last: slot 0 is 198.51.100.1.
inline constexpr std::array<std::uint8_t, 4> fake_ip_at(std::size_t slot) {
  return {FAKEIP_RANGE[0], FAKEIP_RANGE[1], FAKEIP_RANGE[2],
          static_cast<std::uint8_t>(slot + FAKEIP_FIRST_HOST)};
}

// The slot an address occupies, or nullopt when it is not ours or is a host
// byte the table never uses (.0 and .255, which are in the range but not in
// service).
inline constexpr std::optional<std::size_t> fake_ip_slot_of(
    const std::array<std::uint8_t, 4> &v4) {
  if (!in_fake_range(v4)) {
    return std::nullopt;
  }
  const std::size_t host = v4[3];
  if (host < FAKEIP_FIRST_HOST || host >= FAKEIP_FIRST_HOST + FAKEIP_CAPACITY) {
    return std::nullopt;
  }
  return host - FAKEIP_FIRST_HOST;
}

// The IPv6 spelling of the same answer: ::ffff:198.51.100.N, the RFC 4291
// v4-mapped form in network order -- ten zero bytes, then ff ff, then the four
// octets.  One table serving both families is the point: a v6-only application
// and a v4-only one cannot end up with two fakes for one name, and T3 gets a
// single lookup path instead of two address caches that can disagree.
inline constexpr std::array<std::uint8_t, 16> fake_ip_v4_mapped(
    const std::array<std::uint8_t, 4> &v4) {
  std::array<std::uint8_t, 16> out{};  // value-initialised: all ten zeros
  out[10] = 0xff;
  out[11] = 0xff;
  out[12] = v4[0];
  out[13] = v4[1];
  out[14] = v4[2];
  out[15] = v4[3];
  return out;
}

// The uint32 shape an IpAddr carries (schema.hpp's v4_addr): the VALUE
// asio's address_v4::to_uint() reports, most significant octet first, so
// 127.0.0.1 is 0x7f000001.  Not a memory layout -- do not memcpy this.
inline constexpr std::uint32_t fake_ip_to_u32(
    const std::array<std::uint8_t, 4> &v4) {
  return (static_cast<std::uint32_t>(v4[0]) << 24) |
         (static_cast<std::uint32_t>(v4[1]) << 16) |
         (static_cast<std::uint32_t>(v4[2]) << 8) |
         static_cast<std::uint32_t>(v4[3]);
}

inline constexpr std::array<std::uint8_t, 4> fake_ip_from_u32(
    std::uint32_t u) {
  return {static_cast<std::uint8_t>((u >> 24) & 0xff),
          static_cast<std::uint8_t>((u >> 16) & 0xff),
          static_cast<std::uint8_t>((u >> 8) & 0xff),
          static_cast<std::uint8_t>(u & 0xff)};
}

// ------------------------------------------------- names not to fabricate (T1)

// A fake works by carrying the name in the CONNECT, so it only makes sense for
// a name whose traffic is going to be proxied.  Every rule below is a case
// where inventing an address would break something that never reaches the proxy
// at all, and the caller should resolve those exactly as it does today.  The
// set is deliberately small and boring -- one line per protocol that has its
// own answer, no clever heuristics.

// DNS names are case-insensitive, so fold before matching: "WPAD" and "wpad"
// name the same host and must get the same verdict.  ASCII only, which is what
// a resolver hands a hook.
inline constexpr char fakeip_lower(char c) {
  return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

inline constexpr bool fakeip_ends_with(std::string_view name,
                                       std::string_view suffix) {
  if (name.size() < suffix.size()) {
    return false;
  }
  const std::size_t at = name.size() - suffix.size();
  for (std::size_t i = 0; i < suffix.size(); ++i) {
    if (fakeip_lower(name[at + i]) != suffix[i]) {
      return false;
    }
  }
  return true;
}

inline constexpr bool fakeip_lower_case_equal(std::string_view a,
                                              std::string_view b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (fakeip_lower(a[i]) != fakeip_lower(b[i])) {
      return false;
    }
  }
  return true;
}

// The leftmost label, folded.  WPAD is reached as "wpad" or
// "wpad.<domain>", and a rule that substring-matched it would also refuse
// "notwpad.example.com", which is an ordinary host.
inline constexpr bool fakeip_first_label_is(std::string_view name,
                                            std::string_view label) {
  const std::size_t dot = name.find('.');
  const std::string_view first =
      dot == std::string_view::npos ? name : name.substr(0, dot);
  return fakeip_lower_case_equal(first, label);
}

inline constexpr bool fakeip_contains(std::string_view name,
                                      std::string_view needle) {
  for (std::size_t i = 0; i + needle.size() <= name.size(); ++i) {
    bool hit = true;
    for (std::size_t j = 0; j < needle.size(); ++j) {
      if (fakeip_lower(name[i + j]) != needle[j]) {
        hit = false;
        break;
      }
    }
    if (hit) {
      return true;
    }
  }
  return false;
}

// True when a name must be resolved locally, as today.
inline bool no_fake_name(std::string_view name) {
  // A root-relative FQDN ("example.com.") names the same host as without the
  // trailing dot.  Drop it first, or it would look like a name with no suffix
  // and every rule below would miss it.
  if (!name.empty() && name.back() == '.') {
    name.remove_suffix(1);
  }

  if (name.empty()) {
    return true;
  }
  // Single label: NetBIOS, plus "localhost".  Answered by broadcast or the
  // local resolver, and the traffic is SMB/NSP -- never proxied TCP.
  if (name.find('.') == std::string_view::npos) {
    return true;
  }
  // mDNS: answered by the machine next to you, never by the proxy's resolver.
  if (fakeip_ends_with(name, ".local")) {
    return true;
  }
  // Reverse lookups ("7.100.51.198.in-addr.arpa").  Those are queries ABOUT an
  // address; fabricating an address for one is backwards, and it would make the
  // table answer for its own range.
  if (fakeip_ends_with(name, ".arpa")) {
    return true;
  }
  // Active Directory service locations: the _msdcs zone (leading or embedded)
  // and its .msdcs ending.  These drive Kerberos and LDAP against domain
  // controllers found by SRV, not proxied TCP.
  if (fakeip_contains(name, "_msdcs") || fakeip_ends_with(name, ".msdcs")) {
    return true;
  }
  // WPAD: proxy auto-discovery itself.  Faking it is circular -- the script
  // that says how to reach the proxy would have to come through the proxy.
  // Label-exact, and only at the left end, which is where the convention
  // puts it.
  if (fakeip_first_label_is(name, "wpad")) {
    return true;
  }
  // The LDAP DN spelling of an AD domain ("dc=corp,dc=example,dc=com") reaches
  // resolvers from some directory clients.  It is not a hostname.
  if (fakeip_contains(name, "dc=")) {
    return true;
  }
  return false;
}

// The one rule the table cannot guess: the caller's own Active Directory
// suffix.  A name that IS the domain or sits under it belongs to DC locator and
// Kerberos traffic that a socks5 proxy does not carry, so the overload lets T3
// pass the machine's domain (empty means no extra rule).  It is a parameter
// rather than a guess because guessing wrong would either fake names it must
// not touch, or refuse names it should fake.
inline bool no_fake_name(std::string_view name, std::string_view ad_suffix) {
  if (no_fake_name(name)) {
    return true;
  }
  if (ad_suffix.empty()) {
    return false;
  }
  if (fakeip_lower_case_equal(name, ad_suffix)) {
    return true;
  }
  // A child of the domain: the suffix at the end, with a label boundary in
  // front of it, so "notcorp.example.com" is not a match for "corp.example.com".
  if (name.size() > ad_suffix.size() && fakeip_ends_with(name, ad_suffix)) {
    const std::size_t at = name.size() - ad_suffix.size() - 1;
    return name[at] == '.';
  }
  return false;
}

// ------------------------------------------------------------------ the table

// Thread safety: NONE.  No mutex, no atomics anywhere below.  A detour can be
// entered from several threads at once, so the caller owns the serialisation
// (T3 wraps one lock around the single global table).  Stated here rather than
// assumed: every method is plain sequential code over one fixed array.

// One candidate address.  An empty name means the slot is free; a free slot may
// still be in quarantine, which is what reusable_at is for.
struct fake_ip_slot {
  std::string name;
  std::size_t inflight = 0;       // pinned by a live connection: never evict
  std::uint64_t last_use = 0;     // touch clock, orders the LRU
  std::uint64_t reusable_at = 0;  // issue again once the allocation clock passes
  bool used_once = false;         // separates never-issued from freshly freed
};

// Names in, fake addresses out, and back again.
class fake_ip_table {
public:
  using octets = std::array<std::uint8_t, 4>;

  // excluded is the proxy's own address when it is a literal IPv4: the table
  // must never hand out the address of the thing it tunnels to, because a fake
  // that IS the proxy turns every connect into a loop.  An address outside the
  // range excludes nothing, and the default -- 0.0.0.0, which is not a fake --
  // excludes nothing either.  This is only the early form of exclude() below:
  // one path, one set of rules, whether the caller knows the address at
  // construction or learns it from parse_proxy_url halfway through a run.
  explicit fake_ip_table(
      octets excluded = octets{},
      std::size_t quarantine = FAKEIP_DEFAULT_QUARANTINE)
      : quarantine_(quarantine) {
    exclude(excluded);
  }

  fake_ip_table(const fake_ip_table &) = delete;
  fake_ip_table &operator=(const fake_ip_table &) = delete;

  // Take an address out of circulation for the rest of this table's life.
  //
  // Constructor-only exclusion was the gap: the proxy literal is not known
  // until the user supplies one, and parse_proxy_url accepts ANY dotted IPv4,
  // so "198.51.100.7:1080" is a legal endpoint that sits inside the range this
  // table hands out.  Without a runtime hook the table could answer some other
  // name with the proxy's own address, and every connect to that fake walks
  // straight back into the proxy -- a loop with nothing in a log to explain it.
  //
  // Additive and idempotent: call it as often as you like, for as many
  // addresses as you like (a proxy can move, and a long-lived injectee learns
  // more than one endpoint), and each in-range address costs exactly one slot
  // however many times it is named.  An address outside the range, or the .0
  // and .255 bytes inside it, is not a slot at all and excludes nothing.
  //
  // RETIRING, NOT KEEPING, IS THE DECISION.  If the address is already mapped
  // to a name when it is excluded, that mapping is retired here, immediately,
  // and drops any pin with it.  The alternative -- leave a live row alone --
  // would preserve exactly the state that causes the loop: a name whose fake
  // IS the proxy, warm in a pin, being connected to right now.  A pin normally
  // means "somebody is using this", which is why eviction honours it; here the
  // somebody is using the wrong address, so honouring it honours the bug.
  // Retiring is also the fail-closed direction for the caller: lookup() of the
  // excluded address answers "not one of mine" rather than a stale name, the
  // row cannot be claimed again, and the excluded byte can never be issued
  // again by any path -- free, LRU or otherwise.  The name that lost the row
  // is not lost: asking for it again allocates a DIFFERENT fake for it.
  void exclude(const octets &addr) {
    const auto slot = fake_ip_slot_of(addr);
    if (!slot || excluded_[*slot]) {
      return;  // not issuable anyway, or already out of circulation
    }
    excluded_[*slot] = true;
    ++exclusions_;
    if (!slots_[*slot].name.empty()) {
      retire(*slot);  // clears the name and the pin; see the note above
    }
  }

  // True when the table has taken this address out of circulation.  Answers
  // for any octets value, in range or not, so a caller can ask about the
  // endpoint it was handed without knowing whether it is a fake.
  bool excluded(const octets &addr) const {
    const auto slot = fake_ip_slot_of(addr);
    return slot && excluded_[*slot];
  }

  // The fake for a name, creating the mapping when the name is new.  Stable:
  // asking twice for a name that is still held returns the SAME address, never
  // a second one, because an application that resolves a host twice must not
  // find it in two places.  nullopt means the table has nothing to give --
  // every slot is pinned, or the quarantine ring is draining -- and the caller
  // must then resolve for real or fail.  It must not guess an address.
  //
  // Steady state, worth knowing before a policy is picked for nullopt: with a
  // non-empty ring the table fills to the whole range, refuses new names while
  // the ring drains (at most one ring-length of them), then serves again -- so
  // roughly half the attempts are refused once it is full.  That is the cheap
  // direction to fail: a refusal means the name resolves for real and is
  // proxied by address, exactly as it is today, while reusing a quarantined row
  // would send one host's sessions to another.
  std::optional<octets> alloc(std::string_view name) {
    if (name.empty()) {
      return std::nullopt;
    }

    ++touch_;
    if (const auto seen = find_name(name)) {
      slots_[*seen].last_use = touch_;  // a repeat query keeps it warm
      return fake_ip_at(*seen);
    }

    // Every attempt for a new name advances the ring clock, successful or not:
    // quarantine is counted in allocations, and a blocked attempt that left the
    // clock alone would never unblock.
    ++allocations_;

    if (const auto free_slot = find_free()) {
      claim(*free_slot, name);
      return fake_ip_at(*free_slot);
    }

    // Full.  Retire the least recently used name with nothing in flight -- INTO
    // quarantine, not into service.  The slot it frees is the last one this
    // attempt may use; using it now would be exactly the reuse this class
    // exists to prevent.
    if (const auto victim = find_lru()) {
      retire(*victim);
    }

    if (const auto aged = find_free()) {
      claim(*aged, name);
      return fake_ip_at(*aged);
    }
    return std::nullopt;
  }

  // The name a fake was issued for.  nullopt for "not one of mine", "mine but
  // evicted" and "mine but never issued" alike.  Deliberately not a touch: a
  // lookup on the way to a CONNECT must not reorder the LRU, and pin() is what
  // keeps an address warm.
  std::optional<std::string> lookup(const octets &fake) const {
    const auto slot = fake_ip_slot_of(fake);
    if (!slot || slots_[*slot].name.empty()) {
      return std::nullopt;
    }
    return slots_[*slot].name;
  }

  // A slot with something in flight cannot be evicted: an evicted name that is
  // still being connected to is the misroute quarantine exists to prevent.
  // Both return false for an address the table does not currently hold, and
  // unpin never wraps a counter around.
  bool pin(const octets &fake) {
    const auto slot = owned_slot(fake);
    if (!slot) {
      return false;
    }
    ++slots_[*slot].inflight;
    return true;
  }

  bool unpin(const octets &fake) {
    const auto slot = owned_slot(fake);
    if (!slot || slots_[*slot].inflight == 0) {
      return false;  // unknown, or an unbalanced call: say so, do not underflow
    }
    --slots_[*slot].inflight;
    return true;
  }

  // The pinned count, for the caller's own bookkeeping and for tests.
  std::size_t pins(const octets &fake) const {
    const auto slot = owned_slot(fake);
    return slot ? slots_[*slot].inflight : 0;
  }

  // Diagnostics for tests and for T3's log lines.
  std::size_t live_names() const {
    std::size_t n = 0;
    for (const auto &row : slots_) {
      if (!row.name.empty()) {
        ++n;
      }
    }
    return n;
  }

  std::size_t quarantined() const {
    std::size_t n = 0;
    for (std::size_t i = 0; i < slots_.size(); ++i) {
      if (slots_[i].name.empty() && !claimable(i)) {
        ++n;
      }
    }
    return n;
  }

  std::size_t quarantine() const { return quarantine_; }

  // Addresses this table can ever hold: the range, minus every in-range
  // exclusion it has been told about, at construction or afterwards.
  std::size_t capacity() const {
    return FAKEIP_CAPACITY - exclusions_;
  }

  // How many addresses are out of circulation.  It is a count rather than the
  // set because the only question a caller has is "how much did that cost", and
  // capacity() is that answer already.
  std::size_t exclusions() const { return exclusions_; }

  // --------------------------------------------- the two clocks, from outside
  //
  // Added for the P6a S2 owner and ADDITIVE on purpose: nothing above this line
  // changes, so every existing caller and every tests/fakeip pin behaves
  // exactly as before.  Both clocks used to advance only inside alloc(), which
  // is right for a table with one caller and wrong for one behind a mutex with
  // two different kinds of event feeding it:
  //
  //   a live connection keeping its name warm   -> note_touched(addr)
  //   time passing at all, draining quarantine  -> note_progress()
  //
  // Without the first, an application that resolves once and then connects a
  // hundred times lets its row sink to the bottom of the LRU while it is being
  // used; a pin keeps a row from being EVICTED, it does not keep the ordering
  // honest, and those are two different promises.
  //
  // Without the second the failure is worse and quieter: the quarantine ring is
  // counted in ALLOCATIONS, so a process that stops resolving has a frozen
  // clock and its retired slots never age out.  Half the range, parked
  // forever -- the exhaustion this design was argued for avoiding, arriving not
  // through load but through idleness.
  bool note_touched(const octets &fake) {
    const auto slot = owned_slot(fake);
    if (!slot) {
      return false;  // not a row: nothing to warm, and no pretending
    }
    slots_[*slot].last_use = ++touch_;
    return true;
  }

  // Advance the ring clock by 'ticks' allocations and report the new value, so
  // a caller or a test can see the drain it just paid for.
  std::uint64_t note_progress(std::size_t ticks = 1) {
    allocations_ += ticks;
    return allocations_;
  }

private:
  std::optional<std::size_t> owned_slot(const octets &fake) const {
    const auto slot = fake_ip_slot_of(fake);
    if (!slot || slots_[*slot].name.empty()) {
      return std::nullopt;
    }
    return slot;
  }

  // Linear on purpose: the table is 254 rows, and a scan keeps this header
  // free of a hash container, of a second index to keep in sync, and of any
  // question about what happens to the map when a slot is retired.
  std::optional<std::size_t> find_name(std::string_view name) const {
    for (std::size_t i = 0; i < slots_.size(); ++i) {
      if (slots_[i].name == name) {
        return i;
      }
    }
    return std::nullopt;
  }

  // Issuable when nothing is in it, it is not an excluded address, and either
  // it has never been used or its quarantine has run out.  This predicate is
  // where the exclusion bites: find_free() is the only way a row is ever
  // claimed, it goes through here, and every exclusion -- constructor or
  // runtime, one row or several -- is therefore honoured on the alloc path
  // without alloc() having to know anything about it.
  bool claimable(std::size_t i) const {
    if (excluded_[i]) {
      return false;
    }
    const fake_ip_slot &row = slots_[i];
    if (!row.used_once) {
      return true;
    }
    return allocations_ >= row.reusable_at;
  }

  std::optional<std::size_t> find_free() const {
    for (std::size_t i = 0; i < slots_.size(); ++i) {
      if (slots_[i].name.empty() && claimable(i)) {
        return i;
      }
    }
    return std::nullopt;
  }

  std::optional<std::size_t> find_lru() const {
    std::optional<std::size_t> victim;
    for (std::size_t i = 0; i < slots_.size(); ++i) {
      const fake_ip_slot &row = slots_[i];
      if (row.name.empty() || row.inflight != 0) {
        continue;  // free, or somebody is using it: not a candidate
      }
      if (!victim || row.last_use < slots_[*victim].last_use) {
        victim = i;
      }
    }
    return victim;
  }

  void claim(std::size_t i, std::string_view name) {
    fake_ip_slot &row = slots_[i];
    row.name.assign(name);
    row.inflight = 0;
    row.last_use = touch_;
    row.reusable_at = 0;
    row.used_once = true;
  }

  void retire(std::size_t i) {
    fake_ip_slot &row = slots_[i];
    row.name.clear();
    row.inflight = 0;
    row.used_once = true;
    row.reusable_at =
        allocations_ + static_cast<std::uint64_t>(quarantine_);
  }

  std::array<fake_ip_slot, FAKEIP_CAPACITY> slots_{};
  std::size_t quarantine_ = FAKEIP_DEFAULT_QUARANTINE;
  // Out-of-circulation marks, one byte per row: a fixed array, no container and
  // no allocation, and O(1) to consult from claimable().  A row is marked for
  // the table's whole life, so there is nothing to clear and nothing to leak
  // when one proxy address is replaced by another.
  std::array<bool, FAKEIP_CAPACITY> excluded_{};
  std::size_t exclusions_ = 0;  // rows marked, so capacity() need not count
  // Both clocks are TICKS, not wall clock: nothing here reads a clock, and
  // every test drives LRU aging and quarantine expiry by the number of alloc()
  // calls it makes, which is why there is no injectable time source to add.
  std::uint64_t touch_ = 0;         // LRU clock: every call is a use
  std::uint64_t allocations_ = 0;   // ring clock: every new-name attempt
};

#endif
