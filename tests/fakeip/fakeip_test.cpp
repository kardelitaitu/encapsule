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

// Tests for the fake-IP name table (ROADMAP P6a T1 + T2).
//
// This is what keeping src/injectee/fakeip.hpp free of winsock buys: the range,
// the round trip, the eviction order, the quarantine ring, the name rules and
// both forms of the exclusion rule are all pinned here, on the host, with no
// process to inject into, no proxy to talk to and no socket ever opened.

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <fakeip.hpp>

#include "test_support.hpp"

namespace {

using octets = std::array<std::uint8_t, 4>;

// Names the rule set accepts (dotted, no reserved suffix), distinct per index.
std::string host_name(std::size_t i) {
  return "host" + std::to_string(i) + ".example.com";
}

std::size_t churn_issued = 0;   // allocations the table answered
std::size_t churn_refused = 0;  // attempts it would not answer

}  // namespace

void range_membership_is_the_prefix() {
  CHECK_EQ(FAKEIP_CAPACITY, std::size_t(254));
  CHECK_EQ(FAKEIP_DEFAULT_QUARANTINE, std::size_t(127));

  const octets first_host{198, 51, 100, 1};
  const octets last_host{198, 51, 100, 254};
  const octets network{198, 51, 100, 0};
  const octets broadcast{198, 51, 100, 255};
  CHECK(in_fake_range(first_host));
  CHECK(in_fake_range(last_host));
  // Membership is the /24: .0 and .255 are never issued, but they are still
  // ours, so a query about one is not a query about a real host.
  CHECK(in_fake_range(network));
  CHECK(in_fake_range(broadcast));

  const octets next_prefix{198, 51, 101, 1};
  const octets test_net3{203, 0, 113, 7};
  const octets loopback{127, 0, 0, 1};
  const octets lan{192, 168, 1, 10};
  CHECK(!in_fake_range(next_prefix));
  CHECK(!in_fake_range(test_net3));
  CHECK(!in_fake_range(loopback));
  CHECK(!in_fake_range(lan));

  // Slots run .1 -> 0 through .254 -> 253; the two reserved bytes have none.
  CHECK_EQ(fake_ip_slot_of(first_host).value_or(9999), std::size_t(0));
  CHECK_EQ(fake_ip_slot_of(last_host).value_or(9999), std::size_t(253));
  CHECK(!fake_ip_slot_of(network));
  CHECK(!fake_ip_slot_of(broadcast));
  CHECK(!fake_ip_slot_of(test_net3));

  const octets built = fake_ip_at(6);
  const octets want{198, 51, 100, 7};
  CHECK_EQ(built, want);
  CHECK_EQ(fake_ip_at(0), first_host);
  CHECK_EQ(fake_ip_at(253), last_host);
}

void v4_mapped_form_is_the_rfc_4291_bytes() {
  const auto mapped = fake_ip_v4_mapped(fake_ip_at(6));  // ::ffff:198.51.100.7
  const std::array<std::uint8_t, 16> want{
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, 7};
  CHECK_EQ(mapped, want);
  CHECK_EQ(mapped.size(), std::size_t(16));
  CHECK_EQ(mapped[0], std::uint8_t(0));
  CHECK_EQ(mapped[9], std::uint8_t(0));
  CHECK_EQ(mapped[10], std::uint8_t(0xff));
  CHECK_EQ(mapped[11], std::uint8_t(0xff));

  // One table for both families: the trailing four octets ARE the v4 fake, so
  // a v6 answer lands on the row the v4 answer used.
  const octets back{mapped[12], mapped[13], mapped[14], mapped[15]};
  const octets want4{198, 51, 100, 7};
  CHECK(in_fake_range(back));
  CHECK_EQ(back, want4);
  CHECK_EQ(fake_ip_v4_mapped(fake_ip_at(0))[15], std::uint8_t(1));
}

void u32_form_is_the_ipaddr_value() {
  const octets fake{198, 51, 100, 7};
  CHECK_EQ(fake_ip_to_u32(fake), std::uint32_t(0xc6336407u));
  const octets loop{127, 0, 0, 1};
  CHECK_EQ(fake_ip_to_u32(loop), std::uint32_t(0x7f000001u));
  CHECK_EQ(fake_ip_from_u32(fake_ip_to_u32(fake)), fake);
  const octets back{0xc6, 0x33, 0x64, 0x07};
  CHECK_EQ(fake_ip_from_u32(0xc6336407u), back);
}

void alloc_round_trips_and_is_stable() {
  fake_ip_table table;
  CHECK_EQ(table.capacity(), FAKEIP_CAPACITY);
  CHECK_EQ(table.quarantine(), FAKEIP_DEFAULT_QUARANTINE);

  const std::string a = "www.example.com";
  const std::string b = "api.example.com";
  const octets want{198, 51, 100, 1};
  const auto first = table.alloc(a);
  CHECK(first.has_value());
  CHECK_EQ(first.value_or(octets{}), want);  // the lowest free slot, first

  // Stable: the same name again gets the SAME address and takes no second
  // slot -- an app that resolves twice must not find its host in two places.
  CHECK_EQ(table.alloc(a).value_or(octets{}), first.value_or(octets{}));
  CHECK_EQ(table.live_names(), std::size_t(1));

  const auto second = table.alloc(b);
  CHECK(second.has_value());
  CHECK(*second != first.value_or(octets{}));
  CHECK_EQ(table.lookup(first.value_or(octets{})).value_or(""), a);
  CHECK_EQ(table.lookup(*second).value_or(""), b);
  CHECK_EQ(table.live_names(), std::size_t(2));

  // Unknown is unknown, in range or not.
  const octets never{198, 51, 100, 200};
  CHECK(!table.lookup(never));
  const octets real{203, 0, 113, 7};
  CHECK(!table.lookup(real));
  // An empty name is nothing to remember: no slot, no crash.
  CHECK(!table.alloc(""));
  CHECK_EQ(table.live_names(), std::size_t(2));
}

void the_table_holds_the_whole_range_once() {
  fake_ip_table table;
  std::vector<octets> given;
  for (std::size_t i = 0; i < FAKEIP_CAPACITY; ++i) {
    const auto f = table.alloc(host_name(i));
    CHECK(f.has_value());
    if (f) {
      given.push_back(*f);
    }
  }
  CHECK_EQ(table.live_names(), FAKEIP_CAPACITY);
  CHECK_EQ(given.size(), FAKEIP_CAPACITY);

  // .1 through .254, each exactly once, each naming the host that asked.
  for (std::size_t i = 0; i < given.size(); ++i) {
    CHECK_EQ(given[i], fake_ip_at(i));
    CHECK_EQ(table.lookup(given[i]).value_or(""), host_name(i));
  }
  const octets network{198, 51, 100, 0};
  const octets broadcast{198, 51, 100, 255};
  CHECK(!table.lookup(network));
  CHECK(!table.lookup(broadcast));
}

void exhaustion_evicts_lru_and_skips_pinned() {
  // No quarantine: this case is only about WHICH row LRU gives up.
  fake_ip_table table{octets{}, 0};
  for (std::size_t i = 0; i < FAKEIP_CAPACITY; ++i) {
    CHECK(table.alloc(host_name(i)).has_value());
  }
  CHECK_EQ(table.live_names(), FAKEIP_CAPACITY);

  const octets busy = fake_ip_at(3);  // 198.51.100.4, host3.example.com
  CHECK(table.pin(busy));
  CHECK(table.pin(busy));
  CHECK_EQ(table.pins(busy), std::size_t(2));

  // host0, host1, host2 were touched first and never again: they are the LRU
  // order.  The fourth new name has to walk OVER the pinned row, because a row
  // with something in flight is not a candidate at all.
  const auto n1 = table.alloc("new1.example.com");
  const auto n2 = table.alloc("new2.example.com");
  const auto n3 = table.alloc("new3.example.com");
  const auto n4 = table.alloc("new4.example.com");

  CHECK_EQ(n1.value_or(octets{}), fake_ip_at(0));
  CHECK_EQ(n2.value_or(octets{}), fake_ip_at(1));
  CHECK_EQ(n3.value_or(octets{}), fake_ip_at(2));
  CHECK_EQ(n4.value_or(octets{}), fake_ip_at(4));

  CHECK_EQ(table.lookup(busy).value_or(""), host_name(3));
  CHECK_EQ(table.pins(busy), std::size_t(2));  // the pin survived the sweep
  CHECK_EQ(table.live_names(), FAKEIP_CAPACITY);
  CHECK_EQ(table.lookup(n4.value_or(octets{})).value_or(""),
           std::string("new4.example.com"));
}

void quarantined_slot_is_not_reissued_early() {
  fake_ip_table table{octets{}, 4};  // a ring of four allocations
  for (std::size_t i = 0; i < FAKEIP_CAPACITY; ++i) {
    CHECK(table.alloc(host_name(i)).has_value());
  }

  const octets victim = fake_ip_at(0);
  CHECK_EQ(table.lookup(victim).value_or(""), host_name(0));

  // Four attempts: each retires one more name and receives nothing, because
  // every slot it just freed is inside the ring.  Being full is not a licence
  // to reuse -- this is exactly the window a stale cache would misroute in.
  for (std::size_t i = 0; i < 4; ++i) {
    CHECK(!table.alloc(host_name(1000 + i)));
  }
  CHECK_EQ(table.live_names(), FAKEIP_CAPACITY - 4);
  CHECK_EQ(table.quarantined(), std::size_t(4));
  CHECK(!table.lookup(victim));  // the evicted name is really gone

  // The fifth attempt is quarantine() allocations after that first eviction,
  // and only now is the victim issuable -- to a different name, by then.
  const auto got = table.alloc("winner.example.com");
  CHECK_EQ(got.value_or(octets{}), victim);
  CHECK_EQ(table.lookup(victim).value_or(""),
           std::string("winner.example.com"));
  CHECK_EQ(table.quarantined(), std::size_t(3));
  CHECK_EQ(table.live_names(), FAKEIP_CAPACITY - 3);
  // The rows retired later are still waiting their turn.
  CHECK(!table.lookup(fake_ip_at(1)));
  CHECK(!table.lookup(fake_ip_at(3)));
}

void churn_never_collides_a_live_name() {
  fake_ip_table table;  // the default half-range ring
  std::map<octets, std::pair<std::string, std::size_t>> last_issued;
  std::size_t late_successes = 0;   // served after the first ring drained
  std::size_t streak = 0;           // consecutive refusals, right now
  std::size_t max_streak = 0;       // the longest such run
  churn_issued = churn_refused = 0;

  for (std::size_t i = 0; i < 600; ++i) {
    const auto f = table.alloc(host_name(i));
    if (!f) {
      ++churn_refused;
      ++streak;
      if (streak > max_streak) {
        max_streak = streak;
      }
      continue;
    }
    streak = 0;
    ++churn_issued;
    // The table's own answer for that address is the name that just asked,
    // never somebody else's.
    CHECK_EQ(table.lookup(*f).value_or(""), host_name(i));
    const auto seen = last_issued.find(*f);
    if (seen != last_issued.end() && seen->second.first != host_name(i)) {
      // Reissued to a different name: legal only after a full ring of
      // allocations has passed since it was last given out.
      CHECK(i - seen->second.second >= table.quarantine());
    }
    last_issued[*f] = {host_name(i), i};
    if (i >= FAKEIP_CAPACITY + table.quarantine() + 1) {
      ++late_successes;
    }
  }

  // Every attempt is accounted for, far more than the whole range was served,
  // the ring did block -- but never for longer than a ring's length, and it
  // resumed on its own rather than deadlocking.  The live set never falls by
  // more than the ring has reserved.
  CHECK_EQ(churn_issued + churn_refused, std::size_t(600));
  CHECK(churn_issued > FAKEIP_CAPACITY);
  CHECK(churn_refused > 0);
  CHECK(max_streak <= table.quarantine());
  CHECK(late_successes > 0);
  CHECK(table.live_names() + table.quarantined() <= FAKEIP_CAPACITY);
  CHECK(table.live_names() >= FAKEIP_CAPACITY - table.quarantine());
}

void the_proxys_own_address_is_never_issued() {
  const octets proxy{198, 51, 100, 7};  // a proxy in the fake range
  fake_ip_table table{proxy, 0};
  CHECK_EQ(table.capacity(), FAKEIP_CAPACITY - 1);

  std::vector<octets> given;
  for (std::size_t i = 0; i < FAKEIP_CAPACITY; ++i) {  // one more than fits
    const auto f = table.alloc(host_name(i));
    if (f) {
      CHECK(*f != proxy);
      given.push_back(*f);
    }
  }
  CHECK_EQ(table.live_names(), FAKEIP_CAPACITY - 1);
  // An empty ring answers every attempt -- the 254th by evicting the LRU --
  // and still never issues the excluded row.
  CHECK_EQ(given.size(), FAKEIP_CAPACITY);
  CHECK(!table.lookup(proxy));  // the table never owns it
  CHECK(!table.pin(proxy));
  // The excluded row is skipped, so the 7th name lands on .8.
  CHECK_EQ(given[6], fake_ip_at(7));

  // An exclusion outside the range costs nothing.
  const octets elsewhere{203, 0, 113, 7};
  fake_ip_table plain{elsewhere, 0};
  CHECK_EQ(plain.capacity(), FAKEIP_CAPACITY);
  CHECK_EQ(plain.alloc("a.example.com").value_or(octets{}), fake_ip_at(0));
}

// The gap the P6a review found: an exclusion could only be declared when the
// table was built, but the proxy literal is only known once parse_proxy_url has
// answered -- and it accepts ANY dotted IPv4, including one inside this range.
// So these cases drive exclude() at run time, on an address the table has
// ALREADY handed out, which is the one that leaves a stale mapping behind.
void excluding_an_in_use_address_retires_its_mapping() {
  fake_ip_table table;  // nothing excluded at construction: all of this is late
  CHECK_EQ(table.capacity(), FAKEIP_CAPACITY);
  for (std::size_t i = 0; i < 7; ++i) {  // .1 through .7
    CHECK(table.alloc(host_name(i)).has_value());
  }
  const octets proxy{198, 51, 100, 7};
  CHECK_EQ(table.lookup(proxy).value_or(""), host_name(6));
  CHECK(table.pin(proxy));  // something is in flight on it, as if connected
  CHECK(table.pin(proxy));
  CHECK_EQ(table.pins(proxy), std::size_t(2));
  CHECK_EQ(table.live_names(), std::size_t(7));

  table.exclude(proxy);

  // Fail-closed: the stale mapping must not survive the exclusion.  A lookup
  // that kept answering host6 here is the proxy loop, with extra steps.
  CHECK(!table.lookup(proxy));
  CHECK(table.excluded(proxy));
  CHECK_EQ(table.live_names(), std::size_t(6));
  // Retirement drops the row AND its pins: a pin is not a reason to keep
  // handing out the proxy's own address, and unpin() then reports "not mine"
  // instead of underflowing a counter that no longer exists.
  CHECK_EQ(table.pins(proxy), std::size_t(0));
  CHECK(!table.pin(proxy));
  CHECK(!table.unpin(proxy));
  CHECK_EQ(table.capacity(), FAKEIP_CAPACITY - 1);
  CHECK_EQ(table.exclusions(), std::size_t(1));

  // Idempotent, in both senses: naming it again costs nothing and retires
  // nothing a second time.
  table.exclude(proxy);
  table.exclude(proxy);
  CHECK_EQ(table.exclusions(), std::size_t(1));
  CHECK_EQ(table.capacity(), FAKEIP_CAPACITY - 1);
  CHECK_EQ(table.live_names(), std::size_t(6));

  // Values that are not rows exclude nothing, in range or out of it -- and the
  // 0.0.0.0 default is one of them, which is why a plain table is plain.
  const octets network{198, 51, 100, 0};
  const octets broadcast{198, 51, 100, 255};
  const octets test_net3{203, 0, 113, 7};
  const octets loopback{127, 0, 0, 1};
  const octets default_addr{};
  for (const octets &a :
       {network, broadcast, test_net3, loopback, default_addr}) {
    table.exclude(a);
    CHECK(!table.excluded(a));
  }
  CHECK_EQ(table.exclusions(), std::size_t(1));
  CHECK_EQ(table.capacity(), FAKEIP_CAPACITY - 1);

  // The NAME survives; only its fake is gone.  Asking again must land
  // somewhere else, and .7 must stay dead underneath it.
  const auto again = table.alloc(host_name(6));
  CHECK(again.has_value());
  CHECK(*again != proxy);
  CHECK_EQ(table.lookup(*again).value_or(""), host_name(6));
  CHECK(!table.lookup(proxy));
  CHECK_EQ(table.live_names(), std::size_t(7));
}

// Never handed out again by any later alloc(): the sweep runs the whole range
// twice over with an empty ring, so eviction keeps walking the table and the
// excluded rows are the lowest free slots it would love to land on.
void a_runtime_exclusion_is_never_issued_again_under_churn() {
  const octets proxy{198, 51, 100, 7};
  const octets moved_to{198, 51, 100, 20};  // a second endpoint, later still
  fake_ip_table table{octets{}, 0};
  for (std::size_t i = 0; i < 30; ++i) {
    CHECK(table.alloc(host_name(i)).has_value());
  }
  table.exclude(proxy);
  table.exclude(moved_to);  // additive: two rows, not one replacing the other
  CHECK_EQ(table.exclusions(), std::size_t(2));
  CHECK_EQ(table.capacity(), FAKEIP_CAPACITY - 2);
  CHECK(!table.lookup(proxy));
  CHECK(!table.lookup(moved_to));

  for (std::size_t i = 0; i < FAKEIP_CAPACITY * 2; ++i) {
    const auto f = table.alloc(host_name(100 + i));
    CHECK(f.has_value());
    if (f) {
      CHECK(*f != proxy);
      CHECK(*f != moved_to);
      CHECK(!table.excluded(*f));  // the table never issues a withheld row
      CHECK_EQ(table.lookup(*f).value_or(""), host_name(100 + i));
    }
  }
  CHECK_EQ(table.live_names(), table.capacity());
  CHECK(!table.lookup(proxy));
  CHECK(!table.lookup(moved_to));
}

// An exclusion declared late has to behave exactly like one declared up front,
// and it has to outrank the quarantine ring rather than join it: a row whose
// wait is over is still not issuable if somebody excluded it.
void exclusion_at_run_time_matches_the_constructor_and_the_ring() {
  const octets proxy{198, 51, 100, 7};
  fake_ip_table built_in{octets{}, 0};
  built_in.exclude(proxy);  // the same fact, learned after construction
  fake_ip_table known_up_front{proxy, 0};
  CHECK_EQ(built_in.capacity(), known_up_front.capacity());
  for (std::size_t i = 0; i < FAKEIP_CAPACITY; ++i) {  // one more than fits
    const auto late = built_in.alloc(host_name(i));
    const auto early = known_up_front.alloc(host_name(i));
    CHECK_EQ(late.has_value(), early.has_value());
    if (late && early) {
      CHECK_EQ(*late, *early);  // the same seam, in the same place
      CHECK(*late != proxy);
    }
  }
  CHECK(!built_in.lookup(proxy));

  // Now the ring: 4 allocations of quarantine, a row excluded while live, and
  // a table that fills to its capacity.  The excluded row ages out of the ring
  // it was retired into -- and must STILL not be issuable.
  fake_ip_table ring{octets{}, 4};
  for (std::size_t i = 0; i < FAKEIP_CAPACITY - 1; ++i) {  // .1 .. .254 minus 1
    CHECK(ring.alloc(host_name(i)).has_value());
  }
  const octets third{198, 51, 100, 3};
  ring.exclude(third);  // live as host2, and the lowest row in the scan order
  CHECK(!ring.lookup(third));
  CHECK_EQ(ring.capacity(), FAKEIP_CAPACITY - 1);
  CHECK_EQ(ring.live_names(), FAKEIP_CAPACITY - 2);
  const auto spare = ring.alloc("spare.example.com");  // the last untouched row
  CHECK_EQ(spare.value_or(octets{}), fake_ip_at(FAKEIP_CAPACITY - 1));
  CHECK_EQ(ring.live_names(), ring.capacity());

  for (std::size_t i = 0; i < 4; ++i) {  // four evictions, four refusals
    CHECK(!ring.alloc(host_name(900 + i)));
  }
  // 254 rows, 5 of them empty now: the 4 the ring just took plus the excluded
  // one, which is empty forever.
  CHECK_EQ(ring.live_names(), FAKEIP_CAPACITY - 5);
  // Four rows in the ring plus the excluded one: quarantined() answers "free
  // and not issuable", and an excluded row is that forever.
  CHECK_EQ(ring.quarantined(), std::size_t(5));

  // The fifth attempt wins -- on .1, the first row whose wait ran out, NOT on
  // .3, whose wait ran out too.  That is the exclusion outranking the ring.
  const auto aged = ring.alloc("late.example.com");
  CHECK_EQ(aged.value_or(octets{}), fake_ip_at(0));
  CHECK(*aged != third);
  CHECK_EQ(ring.lookup(fake_ip_at(0)).value_or(""),
           std::string("late.example.com"));
  CHECK(!ring.lookup(third));
  CHECK(!ring.pin(third));
}

void pin_and_unpin_bookkeeping() {
  fake_ip_table table;
  const auto f = table.alloc("www.example.com");
  CHECK(f.has_value());
  const octets never{198, 51, 100, 99};
  const octets network{198, 51, 100, 0};
  CHECK(!table.pin(never));    // not issued by this table
  CHECK(!table.pin(network));  // not a row at all
  CHECK(!table.unpin(never));
  CHECK_EQ(table.pins(never), std::size_t(0));

  CHECK(table.pin(*f));
  CHECK(table.pin(*f));
  CHECK_EQ(table.pins(*f), std::size_t(2));
  CHECK(table.unpin(*f));
  CHECK(table.unpin(*f));
  CHECK(!table.unpin(*f));  // one unpin too many: refused, not wrapped
  CHECK_EQ(table.pins(*f), std::size_t(0));
  CHECK_EQ(table.lookup(*f).value_or(""), std::string("www.example.com"));
}

void names_that_must_stay_local() {
  const char *local_only[] = {
      "",          // nothing to resolve
      "localhost",  // single label
      "SERVER",    // NetBIOS -- and proof the rule is not case-based luck
      "x.local",   // mDNS
      "silent.corp.LOCAL",
      "7.100.51.198.in-addr.arpa",       // a reverse lookup
      "_msdcs.corp.example.com",         // AD service locator
      "sites._msdcs.corp.example.com",
      "wpad",
      "WPAD",
      "wpad.corp.example.com",   // the dotted form is the real one
      "wPAd.example.com.",
      "dc=corp,dc=example,dc=com",       // an LDAP DN, not a hostname
      "hostname.",                       // single label with a root dot
  };
  for (const char *name : local_only) {
    CHECK(no_fake_name(name));
  }

  const char *fakeable[] = {
      "www.example.com",
      "a.b.c",                   // three short labels: no rule applies
      "corp.example.com.",       // an ordinary name wearing a root dot
      "intranet.corp.example.net",
      "notwpad.example.com",     // contains the word, not the host
      "198.51.100.7",            // a literal: the rules do not guess about it
  };
  for (const char *name : fakeable) {
    CHECK(!no_fake_name(name));
  }
}

void the_ad_suffix_rule_needs_the_callers_domain() {
  const std::string suffix = "corp.example.com";
  CHECK(no_fake_name("corp.example.com", suffix));      // the domain itself
  CHECK(no_fake_name("CORP.EXAMPLE.COM", suffix));      // folded
  CHECK(no_fake_name("dc1.corp.example.com", suffix));  // a child of it
  CHECK(no_fake_name("a.b.corp.example.com", suffix));
  CHECK(!no_fake_name("notcorp.example.com", suffix));  // a label boundary,
                                                        // not a substring
  CHECK(!no_fake_name("www.example.com", suffix));
  CHECK(!no_fake_name("www.example.com", ""));  // no domain configured at all
  CHECK(no_fake_name("localhost", suffix));     // the base rules still win
}

int main() {
  RUN(range_membership_is_the_prefix);
  RUN(v4_mapped_form_is_the_rfc_4291_bytes);
  RUN(u32_form_is_the_ipaddr_value);
  RUN(alloc_round_trips_and_is_stable);
  RUN(the_table_holds_the_whole_range_once);
  RUN(exhaustion_evicts_lru_and_skips_pinned);
  RUN(quarantined_slot_is_not_reissued_early);
  RUN(churn_never_collides_a_live_name);
  RUN(the_proxys_own_address_is_never_issued);
  RUN(excluding_an_in_use_address_retires_its_mapping);
  RUN(a_runtime_exclusion_is_never_issued_again_under_churn);
  RUN(exclusion_at_run_time_matches_the_constructor_and_the_ring);
  RUN(pin_and_unpin_bookkeeping);
  RUN(names_that_must_stay_local);
  RUN(the_ad_suffix_rule_needs_the_callers_domain);

  std::printf("churn: %zu issued, %zu refused\n", churn_issued, churn_refused);
  return test_failures;
}
