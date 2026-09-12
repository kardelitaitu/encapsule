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

// UDP state, with no socket in sight (ROADMAP P7 dossier (1) and (5), P7-S4).
//
// What a socks5 UDP ASSOCIATE sets up, and what each application socket has
// queued against it, in one place -- so the pump can be a thin loop that asks
// questions and does the socket work itself.  This module never opens, reads,
// writes or closes anything: no winsock type appears here.  A socket travels as
// std::uintptr_t, which is what a SOCKET is on Windows, and an address as 16
// octets plus a port.  That is the whole reason the caps, the drop counters and
// the quarantine of recycled handles are testable in tests/udp on a host with
// no proxy, no peer and nothing to close.
//
// Every function here is inline, so unlike socks5.hpp any number of translation
// units in one binary may include it.  One instance of each table IS one
// process's UDP state, so the owner picks where they live: the pump will make
// them DLL globals.
//
// Thread safety: NONE, deliberately.  The pump is a single thread, and a lock
// here would have to be taken on the hook path, where blocking is not an option
// and DllMain must not wait for one.  Reentrancy rule for the pump: nothing
// calls back into this module from inside a call to it.  Rows never move (the
// storage is a fixed array), so a pointer into a table outlives any later call
// except one that retires or evicts that row -- do not hold one across those.
//
// No reports leave this file either, by the dossier's own rule: one per
// association and per peer, never per datagram, because the queues below are
// the only unbounded thing in the design.

#ifndef ENCAPSULE_INJECTEE_UDP_STATE
#define ENCAPSULE_INJECTEE_UDP_STATE

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

// The atyp values a relay uses in a UDP header.  These mirror the constants in
// socks5.hpp but are named apart on purpose: the pump includes both headers in
// one translation unit, and two names for one constant would not survive it.
inline constexpr std::uint8_t UDP_ATYP_IPV4 = 1;
inline constexpr std::uint8_t UDP_ATYP_DOMAINNAME = 3;
inline constexpr std::uint8_t UDP_ATYP_IPV6 = 4;

// Hard caps, process-wide rather than tunables: they are what keeps an injected
// DLL from growing without bound inside somebody else's address space.
inline constexpr std::size_t UDP_ASSOCIATION_MAX = 32;  // live ASSOCIATEs
inline constexpr std::size_t UDP_STATE_MAX_ROWS = 256;  // app sockets tracked
inline constexpr std::size_t UDP_QUEUE_MAX_DATAGRAMS = 64;  // per socket, per
                                                            // direction
inline constexpr std::size_t UDP_QUEUE_MAX_BYTES = 1024 * 1024;  // ditto
// How many insertions must pass before a retired socket value may come back.
// A recycled handle is the P4 closesocket hazard exactly: the OS gives the next
// socket the number the last one died with, and letting it inherit a dead
// peer's queues delivers one application's datagrams to another.
inline constexpr std::size_t UDP_KEY_QUARANTINE_INSERTIONS = 256;
// An association with no traffic and no reference for this long is reaped.  In
// ticks, because this module owns no clock: the pump ticks it once a second.
inline constexpr std::uint64_t UDP_IDLE_LIMIT_TICKS = 30;

inline constexpr std::size_t UDP_NO_ROW = static_cast<std::size_t>(-1);

// ---------------------------------------------------------------- endpoints

// An address the way a relay states it: the family, sixteen octets (four used
// for v4, the rest zero by construction so equality is a straight compare) and
// a port in host order.
struct udp_endpoint {
  std::uint8_t atyp = 0;
  std::array<std::uint8_t, 16> octets{};
  std::uint16_t port = 0;

  friend constexpr bool operator==(const udp_endpoint &a,
                                   const udp_endpoint &b) {
    return a.atyp == b.atyp && a.port == b.port && a.octets == b.octets;
  }
  friend constexpr bool operator!=(const udp_endpoint &a,
                                   const udp_endpoint &b) {
    return !(a == b);
  }
};

// Address bytes on the wire for a family, port excluded; nullopt for anything a
// UDP header may not carry.  A name is refused: the relay delegates UDP
// endpoints as addresses, and guessing a length for a name is how a parser
// walks off into the payload.
inline constexpr std::optional<std::size_t> udp_endpoint_length(
    std::uint8_t atyp) {
  if (atyp == UDP_ATYP_IPV4) {
    return 4;
  }
  if (atyp == UDP_ATYP_IPV6) {
    return 16;
  }
  return std::nullopt;
}

// "Address then port, big endian" from a span that holds nothing else.  Short,
// long, unknown family or missing bytes is nullopt, and the caller drops the
// packet -- which is what an undecodable packet is.
inline constexpr std::optional<udp_endpoint> udp_endpoint_decode(
    std::uint8_t atyp, const std::uint8_t *bytes, std::size_t size) {
  const auto len = udp_endpoint_length(atyp);
  if (!len || bytes == nullptr || size != *len + 2) {
    return std::nullopt;
  }
  udp_endpoint out;
  out.atyp = atyp;
  for (std::size_t i = 0; i < *len; ++i) {
    out.octets[i] = bytes[i];
  }
  out.port = static_cast<std::uint16_t>((bytes[*len] << 8) | bytes[*len + 1]);
  return out;
}

// The four octets behind a v4 endpoint, for a caller filling a sockaddr_in.  A
// v6 endpoint is not a v4 one, whatever it was mapped from.
inline constexpr std::optional<std::array<std::uint8_t, 4>>
udp_endpoint_as_v4(const udp_endpoint &endpoint) {
  if (endpoint.atyp != UDP_ATYP_IPV4) {
    return std::nullopt;
  }
  return std::array<std::uint8_t, 4>{endpoint.octets[0], endpoint.octets[1],
                                     endpoint.octets[2], endpoint.octets[3]};
}

// --------------------------------------------------------------- association

// One socks5 UDP ASSOCIATE: the control socket that made it, the relay socket
// datagrams go to, the address the relay assigned, and who still uses it.
struct udp_association {
  std::uintptr_t control = 0;
  std::uintptr_t relay = 0;
  udp_endpoint bound{};
  int refcount = 0;
  std::uint64_t generation = 0;
  std::uint64_t last_use = 0;
};

// A slot plus the generation that filled it.  A bare index would let a caller
// keep using an association that died and was replaced -- the same recycling
// hazard the socket keys below are quarantined against.
struct udp_association_ref {
  std::size_t slot = UDP_NO_ROW;
  std::uint64_t generation = 0;

  bool valid() const { return slot != UDP_NO_ROW; }

  friend constexpr bool operator==(const udp_association_ref &a,
                                   const udp_association_ref &b) {
    return a.slot == b.slot && a.generation == b.generation;
  }
};

// The associations.  Failing to open one is survivable (no relay, the pump
// fails the ASSOCIATE); silently dropping a live one would strand a relay
// socket, so nothing here evicts an association.  They die by refcount or by
// reap_idle, both driven by the pump.
class udp_association_table {
public:
  // The same control socket asking twice gets the same association back: one
  // ASSOCIATE must not set up two relays because the hook ran twice.
  udp_association_ref open(std::uintptr_t control, std::uintptr_t relay,
                           const udp_endpoint &bound, std::uint64_t tick) {
    for (std::size_t i = 0; i < rows_.size(); ++i) {
      if (rows_[i].used && rows_[i].state.control == control) {
        rows_[i].state.last_use = tick;
        return udp_association_ref{i, rows_[i].generation};
      }
    }
    for (std::size_t i = 0; i < rows_.size(); ++i) {
      if (rows_[i].used) {
        continue;
      }
      udp_association &row = rows_[i].state;
      row = udp_association{};
      row.control = control;
      row.relay = relay;
      row.bound = bound;
      row.last_use = tick;
      rows_[i].used = true;
      ++rows_[i].generation;  // never rewound, so a stale ref can only die
      ++live_;
      return udp_association_ref{i, rows_[i].generation};
    }
    return udp_association_ref{};  // 32 is 32
  }

  const udp_association *get(const udp_association_ref &ref) const {
    return peek(ref);
  }

  void touch(const udp_association_ref &ref, std::uint64_t tick) {
    udp_association *row = row_of(ref);
    if (row) {
      row->last_use = tick;
    }
  }

  // About to use the relay: hold it.  Nothing in flight is reaped, and the last
  // one out turns the association off.
  bool acquire(const udp_association_ref &ref) {
    udp_association *row = row_of(ref);
    if (!row) {
      return false;
    }
    ++row->refcount;
    return true;
  }

  // The record, when this release killed it -- the caller closes both sockets
  // and never needs a second visit.  nullopt for "still live", and equally for
  // a reference to something already gone: releasing after death is a no-op
  // rather than a second close of a handle that is somebody else's now.
  std::optional<udp_association> release(const udp_association_ref &ref,
                                         std::uint64_t tick) {
    udp_association *row = row_of(ref);
    if (!row) {
      return std::nullopt;
    }
    if (row->refcount > 0) {
      --row->refcount;
    }
    if (row->refcount > 0) {
      row->last_use = tick;
      return std::nullopt;
    }
    const udp_association died = *row;
    close_row(ref.slot);
    return died;
  }

  // Everything at or past the idle limit and holding no reference, handed over
  // so the caller can do the socket work.  Exactly 30 ticks counts: that is the
  // deal the constant makes.
  std::vector<udp_association> reap_idle(std::uint64_t tick) {
    std::vector<udp_association> died;
    for (std::size_t i = 0; i < rows_.size(); ++i) {
      if (!rows_[i].used || rows_[i].state.refcount > 0) {
        continue;
      }
      if (tick < rows_[i].state.last_use) {
        continue;  // a clock that went backwards is not an expiry
      }
      if (tick - rows_[i].state.last_use < UDP_IDLE_LIMIT_TICKS) {
        continue;
      }
      died.push_back(rows_[i].state);
      close_row(i);
    }
    return died;
  }

  std::size_t live() const { return live_; }
  std::size_t capacity() const { return UDP_ASSOCIATION_MAX; }

private:
  struct row_type {
    udp_association state;
    bool used = false;
    std::uint64_t generation = 0;
  };

  // The two halves of the same lookup: a const read for callers that only want
  // to see, and a mutable one for the methods that change a reference count.
  const udp_association *peek(const udp_association_ref &ref) const {
    if (!ref.valid() || ref.slot >= rows_.size()) {
      return nullptr;
    }
    const row_type &row = rows_[ref.slot];
    if (!row.used || row.generation != ref.generation) {
      return nullptr;
    }
    return &row.state;
  }

  udp_association *row_of(const udp_association_ref &ref) {
    if (!ref.valid() || ref.slot >= rows_.size()) {
      return nullptr;
    }
    row_type &row = rows_[ref.slot];
    if (!row.used || row.generation != ref.generation) {
      return nullptr;
    }
    return &row.state;
  }

  void close_row(std::size_t i) {
    rows_[i].state = udp_association{};
    rows_[i].used = false;  // the generation stays: it is the stale-ref guard,
                            // not per-association data
    --live_;
  }

  std::array<row_type, UDP_ASSOCIATION_MAX> rows_{};
  std::size_t live_ = 0;
};

// -------------------------------------------------- per-socket UDP state

// What the hook knows about one application socket.
enum class udp_socket_type : std::uint8_t {
  unknown,
  stream,  // SOCK_STREAM: never ours, whatever else is true of it
  dgram,   // SOCK_DGRAM: the kind this module can carry
};

// One datagram, owned.  A zero-length payload is a real datagram, not an empty
// queue: UDP can carry one, and so does this.
struct udp_datagram {
  udp_endpoint peer{};
  std::vector<std::uint8_t> payload;
};

struct udp_state {
  std::uintptr_t app = 0;
  bool has_peer = false;
  udp_endpoint peer{};  // who it is talking to, once the pump knows
  udp_socket_type type = udp_socket_type::unknown;
  bool takeover = false;  // the pump adopted this socket's traffic
  bool permanently_unmanaged = false;  // decided once, never revisited
  std::vector<udp_datagram> tx;  // app -> relay
  std::vector<udp_datagram> rx;  // relay -> app
  std::size_t tx_bytes = 0;
  std::size_t rx_bytes = 0;
  int pinned = 0;
  std::uint64_t last_use = 0;
};

// The outcome of a push: taken, taken after something older went away, or not
// taken at all.  Silent loss is the one answer this module must not give: the
// counters are how anyone learns the application is dropping datagrams.
enum class udp_push {
  accepted,
  dropped_oldest,
  refused,
};

// Rows for application sockets, keyed by the socket value.
class udp_state_table {
public:
  udp_state_table() = default;
  udp_state_table(const udp_state_table &) = delete;
  udp_state_table &operator=(const udp_state_table &) = delete;

  // The row for a socket, created on first sight, touched on every call.
  // nullptr says this module will not track it: the value is inside a retired
  // socket's quarantine (a recycled handle, whose old queues must not come back
  // with it), or all 256 rows are pinned and nothing may be evicted.  The
  // caller then leaves the socket alone, which is today's behaviour and not a
  // failure.
  udp_state *open(std::uintptr_t app, std::uint64_t tick) {
    for (std::size_t i = 0; i < rows_.size(); ++i) {
      if (rows_[i].used && rows_[i].state.app == app) {
        rows_[i].state.last_use = tick;
        return &rows_[i].state;
      }
    }
    ++insertions_;
    prune_quarantine();
    if (is_quarantined(app)) {
      return nullptr;
    }
    const auto slot = find_slot_for(app);
    if (!slot) {
      return nullptr;
    }
    row_type &row = rows_[*slot];
    if (row.used) {
      // Eviction: whatever it was holding is gone, and that is a loss the
      // caller should be able to count even though no push caused it.
      discarded_ += row.state.tx.size() + row.state.rx.size();
    } else {
      ++rows_used_;
    }
    row.used = true;
    row.state = udp_state{};
    row.state.app = app;
    row.state.last_use = tick;
    return &row.state;
  }

  // A read that neither touches nor creates.
  const udp_state *find(std::uintptr_t app) const {
    for (std::size_t i = 0; i < rows_.size(); ++i) {
      if (rows_[i].used && rows_[i].state.app == app) {
        return &rows_[i].state;
      }
    }
    return nullptr;
  }

  // The socket is closed.  Its row goes now; its VALUE goes into the ring, so
  // for the next UDP_KEY_QUARANTINE_INSERTIONS insertions a socket arriving
  // with this number gets no state at all.
  bool retire(std::uintptr_t app) {
    for (std::size_t i = 0; i < rows_.size(); ++i) {
      if (!rows_[i].used || rows_[i].state.app != app) {
        continue;
      }
      discarded_ += rows_[i].state.tx.size() + rows_[i].state.rx.size();
      rows_[i].state = udp_state{};
      rows_[i].used = false;
      --rows_used_;
      retired_.push_back(
          retired_key{app, insertions_ + UDP_KEY_QUARANTINE_INSERTIONS});
      return true;
    }
    return false;
  }

  // Queued datagrams, oldest first, bounded twice: by count and by bytes.  Over
  // budget throws away the OLDEST until the newcomer fits, because the freshest
  // packet is the one an interactive application still cares about, and every
  // loss is counted.  A datagram that could never fit is refused without
  // emptying anything -- one oversized packet must not cost the whole queue it
  // arrived for.
  udp_push push_tx(std::uintptr_t app, std::uint64_t tick,
                   udp_datagram dgram) {
    return push(app, tick, std::move(dgram), false);
  }

  udp_push push_rx(std::uintptr_t app, std::uint64_t tick,
                   udp_datagram dgram) {
    return push(app, tick, std::move(dgram), true);
  }

  std::optional<udp_datagram> pop_tx(std::uintptr_t app, std::uint64_t tick) {
    return pop(app, tick, false);
  }

  std::optional<udp_datagram> pop_rx(std::uintptr_t app, std::uint64_t tick) {
    return pop(app, tick, true);
  }

  void set_peer(std::uintptr_t app, std::uint64_t tick,
                const udp_endpoint &peer) {
    if (udp_state *row = open(app, tick)) {
      row->peer = peer;
      row->has_peer = true;
    }
  }

  // The SO_TYPE answer, cached: the hook asks once per socket instead of
  // calling into winsock for every datagram.
  void set_type(std::uintptr_t app, std::uint64_t tick,
                udp_socket_type type) {
    if (udp_state *row = open(app, tick)) {
      row->type = type;
    }
  }

  void mark_takeover(std::uintptr_t app, std::uint64_t tick) {
    if (udp_state *row = open(app, tick)) {
      row->takeover = true;
    }
  }

  // Decided not to be ours (a stream socket, a family that cannot be carried):
  // the hook stops asking, and the row carries the decision until it is
  // retired.
  void mark_permanently_unmanaged(std::uintptr_t app, std::uint64_t tick) {
    if (udp_state *row = open(app, tick)) {
      row->permanently_unmanaged = true;
    }
  }

  // Hold a row across the work the pump is doing on its behalf: an in-flight
  // send must not have its queue evicted underneath it.
  bool pin(std::uintptr_t app) {
    udp_state *row = mutable_row(app);
    if (!row) {
      return false;
    }
    ++row->pinned;
    return true;
  }

  bool unpin(std::uintptr_t app) {
    udp_state *row = mutable_row(app);
    if (!row || row->pinned == 0) {
      return false;  // unknown, or one unpin too many: never wraps
    }
    --row->pinned;
    return true;
  }

  std::size_t pins(std::uintptr_t app) const {
    const udp_state *row = find(app);
    return row ? static_cast<std::size_t>(row->pinned) : 0;
  }

  // -------------------------------------------------------- loop prevention
  //
  // The pump's OWN sockets: every control and relay socket it created itself.
  // A hooked sendto from inside the pump must not be captured again, or the
  // module tunnels its own tunnel.  This set is the identity guard from the
  // dossier, and owns() is what the hook consults before it looks at any state.
  void own(std::uintptr_t socket) {
    for (const auto held : owned_) {
      if (held == socket) {
        return;
      }
    }
    owned_.push_back(socket);
  }

  bool unown(std::uintptr_t socket) {
    for (std::size_t i = 0; i < owned_.size(); ++i) {
      if (owned_[i] == socket) {
        owned_.erase(owned_.begin() + static_cast<std::ptrdiff_t>(i));
        return true;
      }
    }
    return false;
  }

  bool owns(std::uintptr_t socket) const {
    if (socket == 0) {
      return false;  // nothing was ever created with this value, so the pump
                    // cannot own it; INVALID_SOCKET (~0) is its own key
    }
    for (const auto held : owned_) {
      if (held == socket) {
        return true;
      }
    }
    return false;
  }

  std::size_t owned_count() const { return owned_.size(); }

  // ---------------------------------------------------------- diagnostics
  std::size_t live_rows() const { return rows_used_; }
  std::size_t capacity() const { return UDP_STATE_MAX_ROWS; }
  std::size_t dropped_datagrams() const { return dropped_; }
  std::size_t discarded_datagrams() const { return discarded_; }
  std::size_t refused_datagrams() const { return refused_; }
  std::uint64_t insertions() const { return insertions_; }
  std::size_t quarantine_setting() const {
    return UDP_KEY_QUARANTINE_INSERTIONS;
  }
  bool quarantined(std::uintptr_t app) const { return is_quarantined(app); }

private:
  struct row_type {
    udp_state state;
    bool used = false;
  };

  struct retired_key {
    std::uintptr_t app;
    std::uint64_t reusable_at;
  };

  udp_push push(std::uintptr_t app, std::uint64_t tick, udp_datagram dgram,
                bool to_rx) {
    udp_state *row = open(app, tick);
    if (!row) {
      ++refused_;
      return udp_push::refused;
    }
    const std::size_t size = dgram.payload.size();
    if (size > UDP_QUEUE_MAX_BYTES) {
      ++refused_;
      return udp_push::refused;  // could never fit: lose it, not the queue
    }
    auto &queue = to_rx ? row->rx : row->tx;
    auto &bytes = to_rx ? row->rx_bytes : row->tx_bytes;
    std::size_t lost = 0;
    while (!queue.empty() &&
           (queue.size() + 1 > UDP_QUEUE_MAX_DATAGRAMS ||
            bytes + size > UDP_QUEUE_MAX_BYTES)) {
      bytes -= queue.front().payload.size();
      queue.erase(queue.begin());
      ++lost;
    }
    dropped_ += lost;
    bytes += size;
    queue.push_back(std::move(dgram));
    return lost == 0 ? udp_push::accepted : udp_push::dropped_oldest;
  }

  std::optional<udp_datagram> pop(std::uintptr_t app, std::uint64_t tick,
                                  bool from_rx) {
    // A drained queue must not start tracking a socket it has never heard
    // about: that is open()'s job, and it costs an insertion and possibly
    // somebody else's row.
    udp_state *row = mutable_row(app);
    if (!row) {
      return std::nullopt;
    }
    row->last_use = tick;
    auto &queue = from_rx ? row->rx : row->tx;
    if (queue.empty()) {
      return std::nullopt;
    }
    udp_datagram next = std::move(queue.front());
    queue.erase(queue.begin());
    auto &bytes = from_rx ? row->rx_bytes : row->tx_bytes;
    bytes -= next.payload.size();
    return next;
  }

  // The row for a socket this table already holds, or nullptr.  Never creates,
  // unlike open().
  udp_state *mutable_row(std::uintptr_t app) {
    for (std::size_t i = 0; i < rows_.size(); ++i) {
      if (rows_[i].used && rows_[i].state.app == app) {
        return &rows_[i].state;
      }
    }
    return nullptr;
  }

  // A free row, else the least recently used row nobody is pinning.
  std::optional<std::size_t> find_slot_for(std::uintptr_t app) {
    for (std::size_t i = 0; i < rows_.size(); ++i) {
      if (!rows_[i].used) {
        return i;
      }
    }
    auto victim = std::optional<std::size_t>{};
    for (std::size_t i = 0; i < rows_.size(); ++i) {
      const udp_state &state = rows_[i].state;
      if (state.pinned != 0 || state.app == app) {
        continue;  // in flight, or the row this key would have taken anyway
      }
      if (!victim || state.last_use < rows_[*victim].state.last_use) {
        victim = i;
      }
    }
    return victim;
  }

  bool is_quarantined(std::uintptr_t app) const {
    for (const auto &key : retired_) {
      if (key.app == app && insertions_ < key.reusable_at) {
        return true;
      }
    }
    return false;
  }

  // A retired key only matters while its ring runs, so forget the rest: the
  // list stays proportional to a ring's worth of churn instead of to the
  // process's lifetime.
  void prune_quarantine() {
    std::vector<retired_key> still;
    for (const auto &key : retired_) {
      if (insertions_ < key.reusable_at) {
        still.push_back(key);
      }
    }
    retired_.swap(still);
  }

  std::array<row_type, UDP_STATE_MAX_ROWS> rows_{};
  std::vector<retired_key> retired_;
  std::vector<std::uintptr_t> owned_;
  std::uint64_t insertions_ = 0;
  std::size_t rows_used_ = 0;
  std::size_t dropped_ = 0;     // oldest-thrown-away under the two budgets
  std::size_t discarded_ = 0;   // lost when a row was evicted or retired
  std::size_t refused_ = 0;     // pushes this module turned down outright
};

#endif
