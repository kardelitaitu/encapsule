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

// Tests for the UDP state module (ROADMAP P7 dossier (1) and (5), P7-S4).
//
// src/injectee/udp_state.hpp holds no socket, so every hazard the pump will
// have to survive is exercised here: the 32-association ceiling, refcounts that
// die at zero and stay dead, the 30-tick idle boundary, 256 rows that evict by
// LRU without ever touching a pinned one, per-socket queues bounded twice over
// with the losses counted, the quarantine that keeps a recycled socket value
// from inheriting a dead peer's queues, the pump's own-socket identity set, and
// headers that arrive hostile.  Nothing here needs a proxy, a peer, or a single
// winsock call.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <udp_state.hpp>

#include "test_support.hpp"

namespace {

constexpr std::uintptr_t kApp = 0x1234;   // an application socket value
constexpr std::uintptr_t kOther = 0x5000; // and a run of them

udp_endpoint v4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d,
                std::uint16_t port) {
  udp_endpoint out;
  out.atyp = UDP_ATYP_IPV4;
  out.octets[0] = a;
  out.octets[1] = b;
  out.octets[2] = c;
  out.octets[3] = d;
  out.port = port;
  return out;
}

// A datagram marked so its position in a queue is readable after eviction.
udp_datagram marked(std::uint8_t mark, std::size_t size) {
  udp_datagram out;
  out.peer = v4(203, 0, 113, 7, 53);
  out.payload.assign(size, mark);
  return out;
}

std::uint8_t front_mark(const udp_state *row, bool from_rx) {
  const auto &queue = from_rx ? row->rx : row->tx;
  return queue.empty() ? 0 : queue.front().payload.front();
}

}  // namespace

void the_caps_are_the_numbers_the_design_promises() {
  CHECK_EQ(UDP_ASSOCIATION_MAX, std::size_t(32));
  CHECK_EQ(UDP_STATE_MAX_ROWS, std::size_t(256));
  CHECK_EQ(UDP_QUEUE_MAX_DATAGRAMS, std::size_t(64));
  CHECK_EQ(UDP_QUEUE_MAX_BYTES, std::size_t(1024 * 1024));
  CHECK_EQ(UDP_KEY_QUARANTINE_INSERTIONS, std::size_t(256));
  CHECK_EQ(UDP_IDLE_LIMIT_TICKS, std::uint64_t(30));
  CHECK_EQ(UDP_ATYP_IPV4, std::uint8_t(1));
  CHECK_EQ(UDP_ATYP_DOMAINNAME, std::uint8_t(3));
  CHECK_EQ(UDP_ATYP_IPV6, std::uint8_t(4));
}

void endpoint_decodes_both_families_and_refuses_hostile_input() {
  const std::uint8_t four[] = {198, 51, 100, 7, 0x1f, 0x90};
  const auto got = udp_endpoint_decode(UDP_ATYP_IPV4, four, sizeof(four));
  CHECK(got.has_value());
  const auto want = v4(198, 51, 100, 7, 8080);
  CHECK_EQ(got.value_or(udp_endpoint{}), want);
  const std::array<std::uint8_t, 4> want4{198, 51, 100, 7};
  const auto raw = udp_endpoint_as_v4(got.value_or(udp_endpoint{}));
  CHECK(raw.has_value());
  CHECK_EQ(raw.value_or(want4), want4);

  std::array<std::uint8_t, 16> six{};
  six[0] = 0xc9;
  six[1] = 0xdb;
  six[15] = 8;
  std::vector<std::uint8_t> eighteen(six.begin(), six.end());
  eighteen.push_back(0x01);
  eighteen.push_back(0xbb);
  const auto v6 = udp_endpoint_decode(UDP_ATYP_IPV6, eighteen.data(),
                                      eighteen.size());
  CHECK(v6.has_value());
  CHECK_EQ(v6.value_or(udp_endpoint{}).port, std::uint16_t(443));
  CHECK_EQ(v6.value_or(udp_endpoint{}).octets, six);
  // v6 is not v4, even though the first octets could be read as either.
  CHECK(!udp_endpoint_as_v4(v6.value_or(udp_endpoint{})));

  // Hostile: one byte short, one byte long, a name (which has no length this
  // module may invent), an unknown family, and no bytes at all.
  const std::uint8_t short_four[] = {1, 2, 3, 0x90};
  CHECK(!udp_endpoint_decode(UDP_ATYP_IPV4, short_four, sizeof(short_four)));
  const std::uint8_t long_six[] = {1, 2, 3, 4, 0x90, 0x00, 0x00};
  CHECK(!udp_endpoint_decode(UDP_ATYP_IPV4, long_six, sizeof(long_six)));
  CHECK(!udp_endpoint_decode(UDP_ATYP_DOMAINNAME, four, sizeof(four)));
  CHECK(!udp_endpoint_decode(std::uint8_t(0), four, sizeof(four)));
  CHECK(!udp_endpoint_decode(std::uint8_t(0x99), four, sizeof(four)));
  CHECK(!udp_endpoint_decode(UDP_ATYP_IPV6, four, sizeof(four)));
  CHECK(!udp_endpoint_decode(UDP_ATYP_IPV4, nullptr, 0));
  CHECK(!udp_endpoint_decode(UDP_ATYP_IPV4, four, 0));
  CHECK(!udp_endpoint_length(UDP_ATYP_DOMAINNAME));
}

void associations_cap_at_32_and_dedupe_by_control_socket() {
  udp_association_table table;
  CHECK_EQ(table.capacity(), UDP_ASSOCIATION_MAX);
  const auto bound = v4(198, 51, 100, 9, 4000);
  for (std::size_t i = 0; i < UDP_ASSOCIATION_MAX; ++i) {
    const auto ref = table.open(kApp + i, kOther + i, bound, i);
    CHECK(ref.valid());
  }
  CHECK_EQ(table.live(), UDP_ASSOCIATION_MAX);

  // 33rd: refused, and an invalid ref is inert rather than a slot 0 alias.
  const auto over = table.open(kApp + 32, kOther + 32, bound, 99);
  CHECK(!over.valid());
  CHECK(table.get(over) == nullptr);
  CHECK(!table.acquire(over));
  CHECK_EQ(table.live(), UDP_ASSOCIATION_MAX);

  // The same control socket asking again is the SAME association, even when the
  // table is full -- one ASSOCIATE must not buy two relays.
  const auto again = table.open(kApp + 5, kOther + 999, bound, 120);
  CHECK(again.valid());
  CHECK_EQ(table.live(), UDP_ASSOCIATION_MAX);
  const auto seen = table.get(again);
  CHECK(seen != nullptr);
  if (seen) {
    CHECK_EQ(seen->relay, kOther + 5);  // the first relay, not the second
    CHECK_EQ(seen->last_use, std::uint64_t(120));  // but the touch landed
    CHECK_EQ(seen->bound, bound);        // the BND the relay assigned is stored
  }
}

void refcount_dies_at_zero_and_release_after_death_is_harmless() {
  udp_association_table table;
  const auto bound = v4(198, 51, 100, 9, 4000);
  const auto ref = table.open(0xA001, 0xB001, bound, 0);
  CHECK(ref.valid());
  CHECK(table.acquire(ref));
  CHECK(table.acquire(ref));

  // Two holders: the first release leaves it alive, the second is the one that
  // says "die now", and it hands the record back so both sockets get closed.
  CHECK(!table.release(ref, 10));
  CHECK_EQ(table.live(), std::size_t(1));
  const auto died = table.release(ref, 20);
  CHECK(died.has_value());
  CHECK_EQ(table.live(), std::size_t(0));
  if (died) {
    CHECK_EQ(died->control, std::uintptr_t(0xA001));
    CHECK_EQ(died->relay, std::uintptr_t(0xB001));
    CHECK_EQ(died->refcount, 0);
  }
  CHECK(table.get(ref) == nullptr);

  // Release after death, again and again: no second close, no crash, no
  // negative live count.
  CHECK(!table.release(ref, 30));
  CHECK(!table.release(ref, 40));
  CHECK(!table.acquire(ref));
  table.touch(ref, 50);  // and a touch on a dead ref is equally inert
  CHECK(table.reap_idle(9999).empty());
  CHECK_EQ(table.live(), std::size_t(0));

  // A reference that was never handed out is not row 0 either.
  const udp_association_ref nobody;
  CHECK(!nobody.valid());
  CHECK(table.get(nobody) == nullptr);
  CHECK(!table.release(nobody, 1));
}

void generation_rejects_a_stale_reference_to_a_reused_slot() {
  udp_association_table table;
  const auto bound = v4(198, 51, 100, 9, 4000);
  const auto first = table.open(0xA001, 0xB001, bound, 0);
  CHECK(table.release(first, 1).has_value());

  // The next association lands in the same slot; the old ref must not reach it.
  const auto second = table.open(0xA002, 0xB002, bound, 2);
  CHECK(second.valid());
  CHECK_EQ(second.slot, first.slot);
  CHECK(second != first);
  CHECK(table.get(first) == nullptr);
  CHECK(!table.acquire(first));
  CHECK(!table.release(first, 3).has_value());
  const auto seen = table.get(second);
  CHECK(seen != nullptr);
  if (seen) {
    CHECK_EQ(seen->control, std::uintptr_t(0xA002));
  }
  CHECK_EQ(table.live(), std::size_t(1));
}

void reap_idle_boundary_is_exactly_thirty_ticks() {
  udp_association_table table;
  const auto bound = v4(198, 51, 100, 9, 4000);
  const auto ref = table.open(0xA001, 0xB001, bound, 0);
  CHECK(ref.valid());

  auto reaped = table.reap_idle(29);
  CHECK(reaped.empty());
  CHECK_EQ(table.live(), std::size_t(1));
  CHECK(table.get(ref) != nullptr);

  reaped = table.reap_idle(UDP_IDLE_LIMIT_TICKS);  // 30: expired, on the tick
  CHECK_EQ(reaped.size(), std::size_t(1));
  if (!reaped.empty()) {
    CHECK_EQ(reaped[0].control, std::uintptr_t(0xA001));
    CHECK_EQ(reaped[0].relay, std::uintptr_t(0xB001));
  }
  CHECK_EQ(table.live(), std::size_t(0));
  CHECK(table.get(ref) == nullptr);

  // Traffic renews it, and a clock that steps backwards never expires it.
  const auto warm = table.open(0xA002, 0xB002, bound, 100);
  CHECK_EQ(table.reap_idle(50).size(), std::size_t(0));
  table.touch(warm, 130);
  CHECK_EQ(table.reap_idle(159).size(), std::size_t(0));
  CHECK_EQ(table.reap_idle(160).size(), std::size_t(1));

  // Something in flight is not idle, however long it has been quiet.
  const auto busy = table.open(0xA003, 0xB003, bound, 0);
  CHECK(table.acquire(busy));
  CHECK(table.acquire(busy));
  CHECK(!table.release(busy, 1).has_value());  // refcount still 1
  CHECK_EQ(table.reap_idle(100000).size(), std::size_t(0));
  CHECK_EQ(table.live(), std::size_t(1));
  CHECK(table.release(busy, 100001).has_value());
  CHECK_EQ(table.live(), std::size_t(0));
}

void row_cap_evicts_lru_never_pinned_and_refuses_when_all_are_hot() {
  udp_state_table table;
  CHECK_EQ(table.capacity(), UDP_STATE_MAX_ROWS);
  for (std::size_t i = 0; i < UDP_STATE_MAX_ROWS; ++i) {
    CHECK(table.open(0x400000 + i, i + 1) != nullptr);
  }
  CHECK_EQ(table.live_rows(), UDP_STATE_MAX_ROWS);

  // Pin the oldest row, then force an insertion: LRU has to step over it and
  // take the next one instead.
  CHECK(table.pin(0x400000));  // the LRU, but untouchable
  CHECK(table.push_rx(0x400000, 300, marked(7, 8)) == udp_push::accepted);
  // A datagram on the row that is about to be evicted, so the loss is
  // countable.  The push reuses its tick, so it does not change the LRU order.
  CHECK(table.push_rx(0x400001, 2, marked(9, 8)) == udp_push::accepted);
  const auto fresh = table.open(0x500000, 301);
  CHECK(fresh != nullptr);
  CHECK_EQ(table.live_rows(), UDP_STATE_MAX_ROWS);
  CHECK(table.find(0x400000) != nullptr);   // the pinned row survived
  CHECK(table.find(0x400001) == nullptr);   // this one did, with its queue
  const auto survivor = table.find(0x400000);
  CHECK(survivor != nullptr);
  if (survivor) {
    CHECK_EQ(survivor->rx.size(), std::size_t(1));  // and its queue is intact
    CHECK_EQ(front_mark(survivor, true), std::uint8_t(7));
  }
  CHECK_EQ(table.pins(0x400000), std::size_t(1));
  CHECK_EQ(table.discarded_datagrams(), std::size_t(1));  // the victim's queue

  // Nothing may be evicted: a new socket gets no row, which the caller reads as
  // "leave it alone".
  for (std::size_t i = 1; i < UDP_STATE_MAX_ROWS; ++i) {
    table.pin(0x400000 + i);  // one of them is gone, which is fine
  }
  CHECK(table.pin(0x500000));
  CHECK(table.open(0x600000, 400) == nullptr);  // 256 rows, every one pinned
  CHECK(table.find(0x600000) == nullptr);
  CHECK_EQ(table.live_rows(), UDP_STATE_MAX_ROWS);
  // One row coming loose is enough to let a new socket in.
  CHECK(table.unpin(0x400002));
  CHECK(table.open(0x600000, 401) != nullptr);
  CHECK(!table.unpin(0x400001));  // unknown row: refused, not wrapped
}

void a_recycled_socket_value_inherits_nothing_until_the_ring_passes() {
  udp_state_table table;
  CHECK(table.open(kApp, 1) != nullptr);
  const auto peer = v4(203, 0, 113, 7, 53);
  table.set_peer(kApp, 2, peer);
  table.set_type(kApp, 2, udp_socket_type::dgram);
  table.mark_permanently_unmanaged(kApp, 2);
  CHECK(table.push_rx(kApp, 3, marked(1, 10)) == udp_push::accepted);
  const auto before = table.find(kApp);
  CHECK(before != nullptr);
  if (before) {
    CHECK_EQ(before->rx.size(), std::size_t(1));
  }

  // The app closes the socket.  P4's hazard is that the very next socket gets
  // the same number.
  CHECK(table.retire(kApp));
  CHECK(table.find(kApp) == nullptr);
  CHECK(table.quarantined(kApp));
  CHECK(table.open(kApp, 4) == nullptr);  // no state, not even a fresh one
  CHECK(table.find(kApp) == nullptr);
  CHECK(table.push_rx(kApp, 5, marked(2, 10)) == udp_push::refused);
  CHECK_EQ(table.refused_datagrams(), std::size_t(1));

  // 254 further insertions are not enough; the ring is 256 wide.  The churn is
  // real sockets with different values, which is exactly what a recycled handle
  // looks like from here.
  // A failed attempt still counts as an insertion -- it is the ring's clock,
  // and a clock that only ran on success would never tick again at all.
  for (std::size_t i = 0; i < UDP_KEY_QUARANTINE_INSERTIONS - 4; ++i) {
    CHECK(table.open(0x900000 + i, 100 + i) != nullptr);
  }
  CHECK(table.quarantined(kApp));
  CHECK(table.open(kApp, 900) == nullptr);

  // Past the ring, the value comes back -- as a NEW row: no peer, no queues,
  // no cached type, no leftover verdict.
  CHECK(table.open(0x920000, 940) != nullptr);
  CHECK(!table.quarantined(kApp));
  const auto after = table.open(kApp, 951);
  CHECK(after != nullptr);
  if (after) {
    CHECK(!after->has_peer);
    CHECK(after->rx.empty());
    CHECK(after->tx.empty());
    CHECK_EQ(after->rx_bytes, std::size_t(0));
    CHECK(after->type == udp_socket_type::unknown);
    CHECK(!after->permanently_unmanaged);
    CHECK(!after->takeover);
    CHECK_EQ(after->pinned, 0);
  }
}

void an_evicted_row_comes_back_empty() {
  udp_state_table table;
  auto first = table.open(0x111, 1);
  CHECK(first != nullptr);
  if (first) {
    first->takeover = true;
    first->permanently_unmanaged = true;
    first->peer = v4(1, 1, 1, 1, 53);
    first->has_peer = true;
  }
  for (std::size_t i = 0; i < UDP_STATE_MAX_ROWS; ++i) {
    CHECK(table.open(0x2000 + i, 10 + i) != nullptr);
  }
  CHECK(table.find(0x111) == nullptr);  // evicted by LRU, unpinned
  const auto back = table.open(0x111, 999);
  CHECK(back != nullptr);
  if (back) {
    CHECK(!back->takeover);
    CHECK(!back->permanently_unmanaged);
    CHECK(!back->has_peer);
  }
}

void count_cap_drops_the_oldest_and_counts_every_loss() {
  udp_state_table table;
  for (std::size_t i = 0; i < 64; ++i) {
    CHECK(table.push_rx(kApp, i, marked(static_cast<std::uint8_t>(i), 4)) ==
          udp_push::accepted);
  }
  const auto full = table.find(kApp);
  CHECK(full != nullptr);
  if (full) {
    CHECK_EQ(full->rx.size(), UDP_QUEUE_MAX_DATAGRAMS);
    CHECK_EQ(full->rx_bytes, std::size_t(256));
    CHECK_EQ(front_mark(full, true), std::uint8_t(0));
  }
  CHECK_EQ(table.dropped_datagrams(), std::size_t(0));

  for (std::uint8_t i = 64; i < 70; ++i) {
    CHECK(table.push_rx(kApp, i + 10, marked(i, 4)) ==
          udp_push::dropped_oldest);
  }
  const auto after = table.find(kApp);
  CHECK(after != nullptr);
  if (after) {
    CHECK_EQ(after->rx.size(), UDP_QUEUE_MAX_DATAGRAMS);  // bounded, not grown
    CHECK_EQ(after->rx_bytes, std::size_t(256));
    CHECK_EQ(front_mark(after, true), std::uint8_t(6));   // six oldest gone
  }
  CHECK_EQ(table.dropped_datagrams(), std::size_t(6));
  // And the queue still drains in order.
  const auto next = table.pop_rx(kApp, 500);
  CHECK(next.has_value());
  if (next) {
    CHECK_EQ(next->payload.front(), std::uint8_t(6));
    CHECK_EQ(next->payload.size(), std::size_t(4));
  }
  CHECK_EQ(table.find(kApp)->rx_bytes, std::size_t(252));
}

void byte_cap_drops_oldest_and_a_stray_giant_is_refused() {
  udp_state_table table;
  const std::size_t big = 100 * 1024;
  for (std::size_t i = 0; i < 20; ++i) {
    const auto res =
        table.push_tx(kApp, i, marked(static_cast<std::uint8_t>(i), big));
    CHECK(res == (i < 10 ? udp_push::accepted : udp_push::dropped_oldest));
  }
  const auto row = table.find(kApp);
  CHECK(row != nullptr);
  if (row) {
    CHECK(row->tx_bytes <= UDP_QUEUE_MAX_BYTES);
    CHECK_EQ(row->tx_bytes, big * 10);  // 11 of them would break the budget
    CHECK_EQ(row->tx.size(), std::size_t(10));
    CHECK_EQ(front_mark(row, false), std::uint8_t(10));
  }
  CHECK_EQ(table.dropped_datagrams(), std::size_t(10));
  const std::size_t dropped = table.dropped_datagrams();
  const std::size_t bytes = row ? row->tx_bytes : 0;
  const std::size_t count = row ? row->tx.size() : 0;

  // Bigger than the whole budget: refused outright, and the queue it arrived
  // for is left exactly as it was.
  const std::size_t giant = UDP_QUEUE_MAX_BYTES + 1;
  CHECK(table.push_tx(kApp, 99, marked(0xfe, giant)) == udp_push::refused);
  CHECK_EQ(table.dropped_datagrams(), dropped);
  CHECK_EQ(table.refused_datagrams(), std::size_t(1));
  const auto same = table.find(kApp);
  CHECK(same != nullptr);
  if (same) {
    CHECK_EQ(same->tx.size(), count);
    CHECK_EQ(same->tx_bytes, bytes);
  }
  // Exactly the budget still fits, and a full-size packet after it costs
  // everything -- the oldest goes, the newcomer stays.
  CHECK(table.push_tx(kApp, 100, marked(0xff, UDP_QUEUE_MAX_BYTES)) ==
        udp_push::dropped_oldest);
  const auto last = table.find(kApp);
  CHECK(last != nullptr);
  if (last) {
    CHECK_EQ(last->tx.size(), std::size_t(1));
    CHECK_EQ(last->tx_bytes, UDP_QUEUE_MAX_BYTES);
    CHECK_EQ(front_mark(last, false), std::uint8_t(0xff));
  }
}

void a_zero_length_datagram_is_a_datagram() {
  udp_state_table table;
  CHECK(table.push_rx(kApp, 1, marked(0, 0)) == udp_push::accepted);
  const auto row = table.find(kApp);
  CHECK(row != nullptr);
  if (row) {
    CHECK_EQ(row->rx.size(), std::size_t(1));
    CHECK_EQ(row->rx_bytes, std::size_t(0));  // zero bytes, one datagram
    CHECK(row->rx.front().payload.empty());
  }
  // It still takes a slot in the count budget, and it drains.
  for (std::size_t i = 0; i < 64; ++i) {
    table.push_rx(kApp, 10 + i, marked(0, 0));  // count is the binding budget
  }
  const auto full = table.find(kApp);
  CHECK(full != nullptr);
  if (full) {
    CHECK_EQ(full->rx.size(), UDP_QUEUE_MAX_DATAGRAMS);
    CHECK_EQ(full->rx_bytes, std::size_t(0));
  }
  const auto popped = table.pop_rx(kApp, 200);
  CHECK(popped.has_value());
  if (popped) {
    CHECK(popped->payload.empty());
  }
  CHECK_EQ(table.find(kApp)->rx_bytes, std::size_t(0));
}

void owns_is_the_loop_prevention_membership() {
  udp_state_table table;
  CHECK(!table.owns(0));  // the INVALID_SOCKET stand-in is never pump-owned
  CHECK(!table.owns(kApp));
  const std::uintptr_t control = 0xC001;
  const std::uintptr_t relay = 0xC002;
  table.own(control);
  table.own(relay);
  table.own(control);  // idempotent: the set is a set
  CHECK_EQ(table.owned_count(), std::size_t(2));
  CHECK(table.owns(control));
  CHECK(table.owns(relay));
  CHECK(!table.owns(kApp));
  CHECK(table.unown(control));
  CHECK(!table.owns(control));
  CHECK(table.owns(relay));  // the other one stays
  CHECK(!table.unown(control));
  CHECK_EQ(table.owned_count(), std::size_t(1));
  table.unown(relay);
  CHECK_EQ(table.owned_count(), std::size_t(0));
}

void caches_and_verdicts_survive_every_touch_a_row_gets() {
  udp_state_table table;
  auto row = table.open(kApp, 1);
  CHECK(row != nullptr);
  if (row) {
    CHECK(row->type == udp_socket_type::unknown);  // not asked yet
    CHECK(!row->has_peer);
    CHECK(!row->takeover);
    CHECK(!row->permanently_unmanaged);
    CHECK_EQ(row->app, kApp);
  }
  table.set_type(kApp, 2, udp_socket_type::stream);
  table.mark_takeover(kApp, 3);
  const auto after = table.find(kApp);
  CHECK(after != nullptr);
  if (after) {
    CHECK(after->type == udp_socket_type::stream);
    CHECK(after->takeover);
    CHECK(!after->permanently_unmanaged);
  }
  // A queue push must not reset what the hook already decided.
  CHECK(table.push_tx(kApp, 4, marked(1, 2)) == udp_push::accepted);
  table.mark_permanently_unmanaged(kApp, 5);
  for (std::size_t i = 0; i < 20; ++i) {
    CHECK(table.open(kApp, 10 + i) != nullptr);
  }
  const auto kept = table.find(kApp);
  CHECK(kept != nullptr);
  if (kept) {
    CHECK(kept->type == udp_socket_type::stream);
    CHECK(kept->takeover);
    CHECK(kept->permanently_unmanaged);
    CHECK_EQ(kept->tx.size(), std::size_t(1));
    CHECK_EQ(kept->last_use, std::uint64_t(29));  // the touches counted
  }
  // An unknown socket is not quietly created by a read.
  CHECK(table.find(0x777) == nullptr);
  CHECK_EQ(table.live_rows(), std::size_t(1));
}

void push_creates_the_row_and_pop_never_invents_one() {
  udp_state_table table;
  // The pump can meet a socket first in a datagram, not in a hook entry.
  CHECK(table.push_tx(kApp, 1, marked(3, 5)) == udp_push::accepted);
  CHECK_EQ(table.live_rows(), std::size_t(1));
  const auto row = table.find(kApp);
  CHECK(row != nullptr);
  if (row) {
    CHECK_EQ(row->tx.size(), std::size_t(1));
    CHECK_EQ(row->rx.size(), std::size_t(0));
  }
  const auto out = table.pop_tx(kApp, 2);
  CHECK(out.has_value());
  if (out) {
    CHECK_EQ(out->payload.front(), std::uint8_t(3));
  }
  // Drained, and nothing invented on the other side.
  CHECK(!table.pop_tx(kApp, 3).has_value());
  CHECK(!table.pop_rx(kApp, 3).has_value());
  CHECK(!table.pop_rx(0x999, 3).has_value());  // unknown socket: nothing to pop
  // An empty read must not have started tracking it: a pump's poll loop would
  // otherwise fill the table with sockets it only asked about.
  CHECK(table.find(0x999) == nullptr);
  CHECK_EQ(table.live_rows(), std::size_t(1));
  CHECK_EQ(table.insertions(), std::uint64_t(1));  // one row, one insertion
  const auto empty_row = table.find(kApp);
  CHECK(empty_row != nullptr);
  if (empty_row) {
    CHECK_EQ(empty_row->tx_bytes, std::size_t(0));  // accounting came back down
    CHECK_EQ(empty_row->rx_bytes, std::size_t(0));
  }
}

int main() {
  RUN(the_caps_are_the_numbers_the_design_promises);
  RUN(endpoint_decodes_both_families_and_refuses_hostile_input);
  RUN(associations_cap_at_32_and_dedupe_by_control_socket);
  RUN(refcount_dies_at_zero_and_release_after_death_is_harmless);
  RUN(generation_rejects_a_stale_reference_to_a_reused_slot);
  RUN(reap_idle_boundary_is_exactly_thirty_ticks);
  RUN(row_cap_evicts_lru_never_pinned_and_refuses_when_all_are_hot);
  RUN(a_recycled_socket_value_inherits_nothing_until_the_ring_passes);
  RUN(an_evicted_row_comes_back_empty);
  RUN(count_cap_drops_the_oldest_and_counts_every_loss);
  RUN(byte_cap_drops_oldest_and_a_stray_giant_is_refused);
  RUN(a_zero_length_datagram_is_a_datagram);
  RUN(owns_is_the_loop_prevention_membership);
  RUN(caches_and_verdicts_survive_every_touch_a_row_gets);
  RUN(push_creates_the_row_and_pop_never_invents_one);

  return test_failures;
}
