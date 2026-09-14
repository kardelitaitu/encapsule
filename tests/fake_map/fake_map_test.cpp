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

// Tests for the fake-address recognizer and the connect-site verdict (P6a S1).
//
// What keeping src/injectee/fake_map.hpp free of winsock CALLS buys is the same
// thing tests/fakeip pins for the table: every address here is a byte array on
// the stack or an 8-byte heap block, no socket is ever opened, no proxy is ever
// contacted and no config is ever read -- the table answer and the
// "proxy configured" flag arrive as arguments.  So the cases that only ever
// happen inside a victim process -- a sockaddr shorter than the struct it
// claims to be, a v6 answer that is not a mapped v4, a fake whose row was
// evicted -- are ordinary unit tests here.  The second half of the file
// (P6a S2) covers the single owner: one table, one mutex, one accessor, OWNED
// answers, and the two clock entry points a resident process needs.  It is
// still nothing but a byte buffer and a std::thread -- the mutex is the only
// new machine, and no socket is opened anywhere in either half.

#include <winsock2.h>  // the address layouts, exactly as fake_map.hpp sees them

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <fake_map.hpp>

#include "test_support.hpp"

namespace {

using octets = std::array<std::uint8_t, 4>;
using blob = std::array<std::uint8_t, sizeof(sockaddr_storage)>;

// An address, spelled as bytes rather than through an API: nothing here calls
// htons/inet_pton, so what the reader is handed is exactly what a victim's own
// code would have written into its sockaddr.
struct made_addr {
  blob bytes{};
  socklen_t len = 0;

  const sockaddr *addr() const {
    return reinterpret_cast<const sockaddr *>(bytes.data());
  }
};

std::uint8_t *raw(made_addr &m) {
  return m.bytes.data();
}

// AF_INET, family + port + the four octets, in the layout sockaddr_in uses.
// 'advertise' lets a test claim a length smaller than the struct it wrote --
// that is the hostile-caller case, not a typo.
made_addr make_v4(const octets &o, std::uint16_t port,
                  socklen_t advertise = static_cast<socklen_t>(
                      sizeof(sockaddr_in))) {
  made_addr m;
  m.len = advertise;
  auto *sa = reinterpret_cast<sockaddr_in *>(raw(m));
  sa->sin_family = AF_INET;
  auto *port_bytes = reinterpret_cast<std::uint8_t *>(&sa->sin_port);
  port_bytes[0] = static_cast<std::uint8_t>(port >> 8);  // wire order, no htons
  port_bytes[1] = static_cast<std::uint8_t>(port & 0xff);
  auto *addr = reinterpret_cast<std::uint8_t *>(&sa->sin_addr);
  for (std::size_t i = 0; i < 4; ++i) {
    addr[i] = o[i];
  }
  return m;
}

// AF_INET6 carrying a caller-supplied 16-byte blob.
made_addr make_v6(const std::array<std::uint8_t, 16> &v6, std::uint16_t port,
                  socklen_t advertise = static_cast<socklen_t>(
                      sizeof(sockaddr_in6))) {
  made_addr m;
  m.len = advertise;
  auto *sa = reinterpret_cast<sockaddr_in6 *>(raw(m));
  sa->sin6_family = AF_INET6;
  auto *port_bytes = reinterpret_cast<std::uint8_t *>(&sa->sin6_port);
  port_bytes[0] = static_cast<std::uint8_t>(port >> 8);
  port_bytes[1] = static_cast<std::uint8_t>(port & 0xff);
  for (std::size_t i = 0; i < 16; ++i) {
    reinterpret_cast<std::uint8_t *>(&sa->sin6_addr)[i] = v6[i];
  }
  return m;
}

// The ::ffff:<v4> spelling fake_ip_v4_mapped() promises.
made_addr make_mapped(const octets &o, std::uint16_t port,
                      socklen_t advertise = static_cast<socklen_t>(
                          sizeof(sockaddr_in6))) {
  return make_v6(fake_ip_v4_mapped(o), port, advertise);
}

// A buffer that is ONLY 'size' bytes long, at the end of its own allocation, so
// a reader that ignores the advertised length runs off a block the victim owns.
struct short_addr {
  std::unique_ptr<std::uint8_t[]> storage;
  socklen_t len = 0;

  const sockaddr *addr() const {
    return reinterpret_cast<const sockaddr *>(storage.get());
  }
};

short_addr make_truncated_v4(const octets &o, std::uint16_t port,
                             std::size_t size) {
  short_addr s;
  s.storage.reset(new std::uint8_t[size]());
  s.len = static_cast<socklen_t>(size);
  auto *p = s.storage.get();
  const auto family = static_cast<std::uint16_t>(AF_INET);
  if (size > 0) {
    p[0] = static_cast<std::uint8_t>(family & 0xff);
  }
  if (size > 1) {
    p[1] = static_cast<std::uint8_t>(family >> 8);
  }
  if (size > 3) {
    p[2] = static_cast<std::uint8_t>(port >> 8);
    p[3] = static_cast<std::uint8_t>(port & 0xff);
  }
  // The octets only fit (and only matter) when the buffer reaches offset 7.
  if (size > 7) {
    for (std::size_t i = 0; i < 4; ++i) {
      p[4 + i] = o[i];
    }
  }
  return s;
}

std::string host(std::size_t i) {
  return "host" + std::to_string(i) + ".example.com";
}

const octets FAKE{198, 51, 100, 7};
const octets FAKE_FIRST{198, 51, 100, 1};
const octets FAKE_LAST{198, 51, 100, 254};
const octets NETWORK{198, 51, 100, 0};
const octets BROADCAST{198, 51, 100, 255};
const octets REAL{93, 184, 216, 34};

}  // namespace

// ------------------------------------------------------------- the layouts

void the_reader_only_trusts_asserted_layouts() {
  // The offsets read_fake_addr reaches through depend on these; if the SDK ever
  // changes one, the header's static_assert stops the build, and this is the
  // same fact stated where a failure names a test instead of a compile.
  CHECK_EQ(sizeof(sockaddr), std::size_t(16));
  CHECK_EQ(sizeof(sockaddr_in), std::size_t(16));
  CHECK_EQ(sizeof(sockaddr_in6), std::size_t(28));
  CHECK_EQ(sizeof(sockaddr_storage), std::size_t(128));
  CHECK_EQ(FAKE_MAP_FAMILY_BYTES, socklen_t(2));
  CHECK_EQ(FAKE_MAP_MAX_LENGTH, socklen_t(128));
}

// ------------------------------------------------------------ the recognizer

void a_v4_fake_is_recognised_with_its_octets_and_port() {
  const auto m = make_v4(FAKE, 443);
  const auto r = read_fake_addr(m.addr(), m.len);

  CHECK(r.readable);
  CHECK(r.in_range);
  CHECK(r.issuable);
  CHECK_EQ(r.v4, FAKE);
  // Slot arithmetic comes from the table: .7 is the sixth address it can own.
  CHECK_EQ(r.slot, std::size_t(6));
  // Host byte order, decoded by hand instead of ntohs(): the reader calls no
  // winsock API, so a test needs nothing on the link line.
  CHECK_EQ(r.port, std::uint16_t(443));

  const auto first = make_v4(FAKE_FIRST, 1);
  CHECK_EQ(read_fake_addr(first.addr(), first.len).slot, std::size_t(0));
  const auto last = make_v4(FAKE_LAST, 65535);
  const auto rl = read_fake_addr(last.addr(), last.len);
  CHECK_EQ(rl.slot, std::size_t(FAKEIP_CAPACITY - 1));
  CHECK_EQ(rl.port, std::uint16_t(65535));
}

void the_v4_mapped_spelling_is_the_same_fake() {
  const auto v4 = make_v4(FAKE, 8080);
  const auto v6 = make_mapped(FAKE, 8080);
  const auto a = read_fake_addr(v4.addr(), v4.len);
  const auto b = read_fake_addr(v6.addr(), v6.len);

  CHECK(b.readable);
  CHECK(b.in_range);
  CHECK(b.issuable);
  CHECK_EQ(b.v4, FAKE);
  CHECK_EQ(b.port, std::uint16_t(8080));
  // One table, one answer: the two spellings must not disagree by even a slot.
  CHECK_EQ(a.slot, b.slot);
  CHECK_EQ(a.in_range, b.in_range);
  CHECK_EQ(a.issuable, b.issuable);

  // And across the whole range, not just the two examples above.
  for (std::size_t host = FAKEIP_FIRST_HOST;
       host < FAKEIP_FIRST_HOST + FAKEIP_CAPACITY; ++host) {
    const octets o{198, 51, 100, static_cast<std::uint8_t>(host)};
    const auto m4 = make_v4(o, 10);
    const auto m6 = make_mapped(o, 10);
    const auto r4 = read_fake_addr(m4.addr(), m4.len);
    const auto r6 = read_fake_addr(m6.addr(), m6.len);
    if (!r4.issuable || !r6.issuable || r4.slot != r6.slot ||
        r4.slot != host - FAKEIP_FIRST_HOST) {
      std::printf("FAIL .100.%zu disagree\n", host);
      ++test_failures;
      break;
    }
  }
}

void a_native_v6_answer_is_never_ours() {
  // 2001:db8::1 -- documentation v6, from a real resolver.  The fake path does
  // not emit v6 at all, so there is nothing to recover.
  std::array<std::uint8_t, 16> native{};
  native[0] = 0x20;
  native[1] = 0x01;
  native[13] = 0x0d;
  native[15] = 0x01;
  const auto native6 = make_v6(native, 443);
  const auto rn = read_fake_addr(native6.addr(), native6.len);
  CHECK(!rn.readable);
  CHECK(!rn.in_range);
  CHECK(!rn.issuable);

  // ::1 and :: are the other two shapes that must not be mistaken for ours:
  // both have the ten leading zeros but NOT the ff ff.
  std::array<std::uint8_t, 16> loopback{};
  loopback[15] = 1;
  const auto lb = make_v6(loopback, 80);
  CHECK(!read_fake_addr(lb.addr(), lb.len).readable);
  const auto unspec = make_v6(std::array<std::uint8_t, 16>{}, 80);
  CHECK(!read_fake_addr(unspec.addr(), unspec.len).readable);

  // A mapped form of somebody else's address is readable but not in range: it
  // is a real v4 host wearing a v6 shell, and faking it would be a misroute.
  const auto other = make_mapped(REAL, 443);
  const auto ro = read_fake_addr(other.addr(), other.len);
  CHECK(ro.readable);
  CHECK(!ro.in_range);
  CHECK(!ro.issuable);
  CHECK_EQ(ro.v4, REAL);

  // ff ff in the wrong place is not a mapped form.
  std::array<std::uint8_t, 16> shifted{};
  shifted[9] = 0xff;
  shifted[10] = 0xff;
  shifted[12] = 198;
  shifted[13] = 51;
  shifted[14] = 100;
  shifted[15] = 7;
  const auto sh = make_v6(shifted, 443);
  CHECK(!read_fake_addr(sh.addr(), sh.len).readable);
}

void the_reader_reads_wire_order_not_winnets_reversed_storage() {
  // THE V6 TRAP, pinned from this side.  to_ip_addr() stores a v6 address
  // REVERSED while to_asio() reads wire order, and P4-1 owns the fix.  This
  // layer must be immune: it decodes the octets where they physically are, so
  // the reversed spelling of our own fake -- which is what a buffer that has
  // been through that round trip looks like -- must NOT be claimed.
  const auto mapped = fake_ip_v4_mapped(FAKE);
  const std::array<std::uint8_t, 16> reversed{
      mapped[15], mapped[14], mapped[13], mapped[12], mapped[11], mapped[10],
      mapped[9],  mapped[8],  mapped[7],  mapped[6],  mapped[5],  mapped[4],
      mapped[3],  mapped[2],  mapped[1],  mapped[0]};

  const auto wrong = make_v6(reversed, 443);
  const auto rw = read_fake_addr(wrong.addr(), wrong.len);
  CHECK(!rw.readable);
  CHECK(!rw.in_range);
  CHECK(!rw.issuable);

  // ...while the same four octets, written where the wire puts them, are ours.
  const auto right = make_mapped(FAKE, 443);
  CHECK(read_fake_addr(right.addr(), right.len).issuable);

  // No IpAddr and no to_ip_addr appear anywhere in fake_map.hpp: the fake path
  // leaves this layer holding a NAME, which is the only spelling that cannot be
  // misread by the two ends that disagree.
  const auto d = fake_connect_verdict(
      right.addr(), right.len, fake_table_answer::borrowed("example.com"),
      true);
  CHECK(d.verdict == fake_verdict::route_by_name);
  CHECK_EQ(d.name, std::string_view("example.com"));
}

void out_of_range_neighbours_are_not_ours() {
  const octets cases[] = {
      {198, 51, 101, 1},   // one past the /24
      {198, 51, 99, 254},  // one before it
      {198, 52, 100, 1},   // one bit off the second octet
      {197, 51, 100, 1},   // ... or the first
      {203, 0, 113, 7},    // TEST-NET-3: documentation, but not ours
      {127, 0, 0, 1},      // loopback must never be captured
      {192, 168, 1, 10},   // a LAN host
      {0, 0, 0, 0},        // unspecified, and the table's "exclude nothing"
      REAL,
  };
  for (const auto &o : cases) {
    const auto m4 = make_v4(o, 443);
    const auto m6 = make_mapped(o, 443);
    const auto r4 = read_fake_addr(m4.addr(), m4.len);
    const auto r6 = read_fake_addr(m6.addr(), m6.len);
    CHECK(r4.readable);  // it is a real v4 address; it just is not ours
    CHECK(!r4.in_range);
    CHECK(!r4.issuable);
    CHECK(!r6.in_range);
    CHECK(!r6.issuable);
    CHECK(!addr_in_fake_range(m4.addr(), m4.len));
    CHECK(!is_fake_ip_addr(m4.addr(), m4.len));
  }
}

void network_and_broadcast_are_in_range_but_never_issued() {
  // Membership is the /24; the table can only own .1 through .254.  A caller
  // still has to treat .0 and .255 as ours -- they are not real hosts -- but no
  // lookup can ever hit them, so they take the nameless-fake path.
  for (const auto &o : {NETWORK, BROADCAST}) {
    const auto m4 = make_v4(o, 443);
    const auto m6 = make_mapped(o, 443);
    const auto r4 = read_fake_addr(m4.addr(), m4.len);
    const auto r6 = read_fake_addr(m6.addr(), m6.len);
    CHECK(r4.readable);
    CHECK(r4.in_range);
    CHECK(!r4.issuable);
    CHECK(r6.in_range);
    CHECK(!r6.issuable);
    CHECK(!fake_ip_slot_of(o));
    CHECK(addr_in_fake_range(m4.addr(), m4.len));
    CHECK(!is_fake_ip_addr(m4.addr(), m4.len));
  }
}

void other_families_and_missing_buffers_are_not_fakes() {
  const auto v4 = make_v4(FAKE, 443);

  // A null name is a legal argument for the length-only probes and every
  // victim-side call site; it must never be dereferenced.
  CHECK(!read_fake_addr(nullptr, 16).readable);
  CHECK(!read_fake_addr(nullptr, 0).readable);
  CHECK(!addr_in_fake_range(nullptr, 16));
  CHECK(!is_fake_ip_addr(nullptr, 16));

  // Non-INET families: the reader looks at the family and stops.
  // AF_UNSPEC, AF_UNIX, and two numbers no address family uses on Windows.
  for (const auto family :
       {std::uint16_t(AF_UNSPEC), std::uint16_t(AF_UNIX), std::uint16_t(100),
        std::uint16_t(999)}) {
    auto m = v4;  // the octets of a real fake, under a family that is not INET
    reinterpret_cast<sockaddr *>(m.bytes.data())->sa_family = family;
    const auto r = read_fake_addr(m.addr(), m.len);
    CHECK(!r.readable);
    CHECK(!r.in_range);
    CHECK(!r.issuable);
  }
}

void a_buffer_shorter_than_its_struct_is_never_interpreted() {
  // THE VICTIM-FAULT CASE.  Each buffer below is allocated at exactly the
  // length it advertises and holds the octets of a real fake, so a reader that
  // takes the word "sockaddr_in" instead of the caller's length both claims a
  // fake that was never offered AND reads past the end of the victim's heap
  // block.  The answer has to be "not ours" on every row.
  const std::size_t sizes[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 12,
                               sizeof(sockaddr_in) - 1};
  for (const std::size_t size : sizes) {
    const auto s = make_truncated_v4(FAKE, 443, size);
    const auto r = read_fake_addr(s.addr(), s.len);
    if (r.readable || r.in_range || r.issuable) {
      std::printf("FAIL truncated AF_INET of %zu bytes was interpreted\n",
                  size);
      ++test_failures;
    }
    CHECK(!addr_in_fake_range(s.addr(), s.len));
    CHECK(!is_fake_ip_addr(s.addr(), s.len));
  }

  // The verdict path is the same: an unreadable buffer is passthrough even with
  // a proxy configured and a table row claiming the address.
  const auto s = make_truncated_v4(FAKE, 443, 8);
  const auto d = fake_connect_verdict(s.addr(), s.len,
                                      fake_table_answer::borrowed("x.com"),
                                      true);
  CHECK(d.verdict == fake_verdict::passthrough);
  CHECK(d.name.empty());
  CHECK(!d.addr.in_range);

  // v6 side: one byte short of sockaddr_in6 hides the last octet of the fake.
  const auto almost = make_mapped(FAKE, 443,
                                 static_cast<socklen_t>(sizeof(sockaddr_in6)) -
                                     1);
  const auto ra = read_fake_addr(almost.addr(), almost.len);
  CHECK(!ra.readable);
  CHECK(!ra.in_range);
}

void an_absurd_length_is_not_an_address_but_a_storage_is() {
  const auto v4 = make_v4(FAKE, 443);
  const auto v6 = make_mapped(FAKE, 443);

  // Too big to be any Windows address shape: not interpreted.
  // Parenthesised on purpose: windef.h still spells max/min as macros, and this
  // is the one place in the suite that wants their numeric_limits versions.
  for (const auto len : {socklen_t(129), socklen_t(1024),
                         (std::numeric_limits<socklen_t>::max)(),
                         (std::numeric_limits<socklen_t>::min)(),
                         socklen_t(-1)}) {
    CHECK(!read_fake_addr(v4.addr(), len).readable);
    CHECK(!read_fake_addr(v6.addr(), len).readable);
  }

  // Exactly the storage ceiling IS tolerated: a caller that passes
  // sizeof(sockaddr_storage) for the v4 it stored inside it is talking about
  // the same fake, and refusing to notice would route it direct.
  const auto as_storage =
      make_v4(FAKE, 443, static_cast<socklen_t>(sizeof(sockaddr_storage)));
  CHECK(read_fake_addr(as_storage.addr(), as_storage.len).issuable);
  const auto padded = make_v4(FAKE, 443, socklen_t(46));
  CHECK(read_fake_addr(padded.addr(), padded.len).issuable);

  const auto v6_in_storage =
      make_mapped(FAKE, 443, static_cast<socklen_t>(sizeof(sockaddr_storage)));
  CHECK(read_fake_addr(v6_in_storage.addr(), v6_in_storage.len).issuable);
}

// ----------------------------------------------------------------- verdicts

void a_hit_in_range_routes_by_the_recovered_name() {
  const auto m = make_v4(FAKE, 443);
  const std::string name = "www.example.com";
  const auto d =
      fake_connect_verdict(m.addr(), m.len, fake_table_answer::borrowed(name),
                           true);

  CHECK(d.verdict == fake_verdict::route_by_name);
  CHECK_EQ(d.name, std::string_view(name));
  // The name is BORROWED: no allocation happens in this layer, so the view must
  // still be pointing at the caller's own bytes rather than a copy.
  CHECK_EQ(d.name.data(), name.data());
  // And the call site keeps the address facts for its pin/unpin.
  CHECK(d.addr.in_range);
  CHECK(d.addr.issuable);
  CHECK_EQ(d.addr.slot, std::size_t(6));
  CHECK_EQ(d.addr.port, std::uint16_t(443));

  // The same verdict with no proxy: a name recovered is still a name to route.
  const auto d2 =
      fake_connect_verdict(read_fake_addr(m.addr(), m.len),
                           fake_table_answer::borrowed(name), false);
  CHECK(d2.verdict == fake_verdict::route_by_name);
  CHECK_EQ(d2.name, std::string_view(name));
}

void an_in_range_miss_refuses_only_when_a_proxy_is_configured() {
  const auto m = make_v4(FAKE, 443);
  const auto r = read_fake_addr(m.addr(), m.len);

  const auto with = fake_connect_verdict(r, fake_table_answer::miss(), true);
  CHECK(with.verdict == fake_verdict::refuse);
  CHECK(with.name.empty());  // nothing to leak into a report
  CHECK(with.addr.in_range);

  const auto without =
      fake_connect_verdict(r, fake_table_answer::miss(), false);
  CHECK(without.verdict == fake_verdict::passthrough);
  CHECK(without.name.empty());

  // nullopt from the table and a row holding nothing are the same answer.
  const std::optional<std::string> empty_row{std::string()};
  CHECK(!fake_table_answer::from_lookup(empty_row).found);
  const auto borrowed_empty =
      fake_connect_verdict(r, fake_table_answer::borrowed(std::string_view()),
                           true);
  CHECK(borrowed_empty.verdict == fake_verdict::refuse);
}

void a_miss_is_what_a_nameless_address_gets_in_both_spellings() {
  // .0 and .255 are in the range and cannot be issued, so their only path is
  // the nameless-fake one -- refuse with a proxy, never quietly direct.
  for (const auto &o : {NETWORK, BROADCAST}) {
    const auto m4 = make_v4(o, 443);
    const auto m6 = make_mapped(o, 443);
    const auto a = fake_connect_verdict(m4.addr(), m4.len,
                                        fake_table_answer::miss(), true);
    const auto b = fake_connect_verdict(m6.addr(), m6.len,
                                        fake_table_answer::miss(), true);
    CHECK(a.verdict == fake_verdict::refuse);
    CHECK(b.verdict == fake_verdict::refuse);
    const auto c = fake_connect_verdict(m4.addr(), m4.len,
                                        fake_table_answer::miss(), false);
    CHECK(c.verdict == fake_verdict::passthrough);
  }
}

void nothing_outside_the_range_ever_routes_or_refuses() {
  // Defence in depth for the caller's mistakes: a row handed back for an
  // address that is not in the range must not capture it, and must not refuse
  // it either.  A real destination is always the original call.
  const std::vector<octets> reals{REAL, {127, 0, 0, 1}, {203, 0, 113, 7},
                                  {198, 51, 101, 7}, {0, 0, 0, 0}};
  for (const auto &o : reals) {
    for (const auto proxy : {true, false}) {
      const auto m4 = make_v4(o, 443);
      const auto m6 = make_mapped(o, 443);
      const auto hit = fake_table_answer::borrowed("not-mine.example.com");
      const auto a = fake_connect_verdict(m4.addr(), m4.len, hit, proxy);
      const auto b = fake_connect_verdict(m6.addr(), m6.len, hit, proxy);
      CHECK(a.verdict == fake_verdict::passthrough);
      CHECK(b.verdict == fake_verdict::passthrough);
      CHECK(a.name.empty());
      CHECK(b.name.empty());
      CHECK(!a.addr.in_range);
    }
  }
}

void the_verdict_never_invents_a_name_it_was_not_given() {
  const auto m = make_v4(FAKE, 443);
  const auto r = read_fake_addr(m.addr(), m.len);

  const auto miss = fake_connect_verdict(r, fake_table_answer::miss(), true);
  CHECK(miss.name.empty());
  const auto direct =
      fake_connect_verdict(r, fake_table_answer::miss(), false);
  CHECK(direct.name.empty());

  // The two overloads agree: one read plus the same policy, either way in.
  const auto via_buffer =
      fake_connect_verdict(m.addr(), m.len, fake_table_answer::borrowed("a.b"),
                           true);
  const auto via_read =
      fake_connect_verdict(r, fake_table_answer::borrowed("a.b"), true);
  CHECK(via_buffer.verdict == via_read.verdict);
  CHECK_EQ(via_buffer.name, via_read.name);
  CHECK_EQ(via_buffer.addr.slot, via_read.addr.slot);

  // And the octet-shaped entry point cannot disagree with the buffer at all.
  const auto spelled = fake_addr_read_of(FAKE, 443);
  CHECK_EQ(spelled.slot, r.slot);
  CHECK(spelled.in_range);
  CHECK(spelled.issuable);
  CHECK_EQ(spelled.port, r.port);
  const auto spelled_out = fake_addr_read_of(REAL, 443);
  CHECK(spelled_out.readable);
  CHECK(!spelled_out.in_range);
}

void a_verdict_is_a_pure_function_of_its_arguments() {
  const auto m = make_v4(FAKE, 443);
  const std::string name = "pure.example.com";
  const auto first =
      fake_connect_verdict(m.addr(), m.len, fake_table_answer::borrowed(name),
                           true);

  // Nothing is cached and nothing is remembered: a hundred calls with the same
  // arguments, interleaved with different arguments, all say the same thing.
  for (int i = 0; i < 100; ++i) {
    const auto again =
        fake_connect_verdict(m.addr(), m.len,
                             fake_table_answer::borrowed(name), true);
    CHECK(again.verdict == first.verdict);
    CHECK_EQ(again.name, first.name);
    CHECK_EQ(again.addr.slot, first.addr.slot);

    fake_connect_verdict(m.addr(), m.len, fake_table_answer::miss(), true);
    fake_connect_verdict(m.addr(), m.len,
                         fake_table_answer::borrowed("other.example"), false);
  }

  // The one input that changes the answer for a miss is the caller's flag, and
  // it never changes it for a hit or for a real address.
  const auto r = read_fake_addr(m.addr(), m.len);
  CHECK(fake_connect_verdict(r, fake_table_answer::miss(), true).verdict ==
        fake_verdict::refuse);
  CHECK(fake_connect_verdict(r, fake_table_answer::miss(), false).verdict ==
        fake_verdict::passthrough);
  CHECK(fake_connect_verdict(r, fake_table_answer::borrowed(name), false)
            .verdict == fake_verdict::route_by_name);
}

void verdict_text_is_fixed_text_for_logs() {
  CHECK_EQ(fake_verdict_text(fake_verdict::route_by_name),
           std::string_view("route_by_name"));
  CHECK_EQ(fake_verdict_text(fake_verdict::refuse), std::string_view("refuse"));
  CHECK_EQ(fake_verdict_text(fake_verdict::passthrough),
           std::string_view("passthrough"));
}

// ----------------------------------------------- against the real table

void the_real_table_and_a_real_sockaddr_round_trip() {
  fake_ip_table table;
  const std::string name = "round.trip.example.com";
  const auto issued = table.alloc(name);
  CHECK(issued.has_value());

  const auto m = make_v4(*issued, 22);
  const auto r = read_fake_addr(m.addr(), m.len);
  CHECK(r.issuable);
  CHECK_EQ(r.v4, *issued);

  // The lookup the caller does under its own lock, fed straight back in.
  const auto row = table.lookup(r.v4);
  CHECK(row.has_value());
  const auto d = fake_connect_verdict(r, fake_table_answer::from_lookup(row),
                                      true);
  CHECK(d.verdict == fake_verdict::route_by_name);
  CHECK_EQ(d.name, std::string_view(name));
  CHECK_EQ(d.name.data(), row->data());  // borrowed, not copied

  // Pin the slot the recognizer named, and it is the row the table holds.
  CHECK(table.pin(r.v4));
  CHECK_EQ(table.pins(r.v4), std::size_t(1));
  CHECK(table.unpin(r.v4));
}

void an_excluded_or_evicted_fake_falls_into_the_miss_path() {
  // The proxy's own address, excluded after the row existed, must stop routing:
  // the table retires the row, so the recognizer still says "in range" while
  // the lookup says "not mine" -- the nameless-fake path, i.e. a refusal.
  fake_ip_table table;
  const auto row = table.alloc("loop.example.com");
  CHECK(row.has_value());
  table.exclude(*row);

  const auto m = make_v4(*row, 1080);
  const auto r = read_fake_addr(m.addr(), m.len);
  CHECK(r.in_range);  // still documented space, never a real host
  const auto d = fake_connect_verdict(r, fake_table_answer::from_lookup(
                                            table.lookup(r.v4)),
                                        true);
  CHECK(d.verdict == fake_verdict::refuse);
  CHECK(d.name.empty());
  CHECK(!table.excluded(REAL));

  // An address in range that was never issued: same answer, same reason.
  const auto never = make_v4(octets{198, 51, 100, 99}, 443);
  const auto rn = read_fake_addr(never.addr(), never.len);
  CHECK(rn.issuable);  // issuable means the table COULD own it, not that it did
  const auto dn = fake_connect_verdict(
      rn, fake_table_answer::from_lookup(table.lookup(rn.v4)), true);
  CHECK(dn.verdict == fake_verdict::refuse);
}

void eviction_turns_a_live_row_back_into_a_refusal() {
  // Fill the table, force its oldest row out, and check that a sockaddr still
  // holding the evicted fake now takes the nameless path: refuse, not direct.
  fake_ip_table table;
  const auto first = table.alloc(host(0));
  CHECK(first.has_value());
  for (std::size_t i = 1; i < FAKEIP_CAPACITY; ++i) {
    if (!table.alloc(host(i))) {  // every slot is now held
      std::printf("FAIL the table filled only %zu of %zu slots\n", i,
                  FAKEIP_CAPACITY);
      ++test_failures;
      break;
    }
  }
  CHECK_EQ(table.live_names(), FAKEIP_CAPACITY);

  // One more name, nothing pinned anywhere: the table retires the LRU row and,
  // because the slot it freed is in quarantine, refuses the newcomer too.  That
  // is the window S1 has to survive -- an address in range with no row behind
  // it, held by an application that cached the answer.
  CHECK(!table.alloc("newcomer.example.com").has_value());
  const auto m = make_v4(*first, 443);
  const auto r = read_fake_addr(m.addr(), m.len);
  CHECK(r.in_range);
  CHECK(r.issuable);  // the slot is issuable space; it simply is not mine now
  const auto stale = table.lookup(r.v4);
  CHECK(!stale.has_value());

  const auto d =
      fake_connect_verdict(r, fake_table_answer::from_lookup(stale), true);
  CHECK(d.verdict == fake_verdict::refuse);
  CHECK(d.name.empty());

  // With no proxy the original call runs: the app learns from the network stack
  // rather than from us, which is exactly what it did before P6 existed.
  const auto e =
      fake_connect_verdict(r, fake_table_answer::from_lookup(stale), false);
  CHECK(e.verdict == fake_verdict::passthrough);

  // The newcomer took nothing either: its attempt was refused, so the row it
  // would have needed is not in the table -- one fewer name is live now.
  CHECK_EQ(table.live_names(), FAKEIP_CAPACITY - 1);
}

void a_domain_shaped_verdict_is_all_the_fake_path_leaves_behind() {
  // The dossier's rule, checked as a property rather than a hope: whatever a
  // caller asks about, this layer's only routing answer is a NAME.  Sweep both
  // spellings of the whole range with and without a row behind them.
  fake_ip_table table;
  std::size_t routed = 0, refused = 0, passed = 0;
  for (std::size_t i = 1; i < 256; ++i) {
    const octets o{198, 51, 100, static_cast<std::uint8_t>(i)};
    const std::string name = host(i);
    std::optional<std::string> row;
    if (i < 64) {
      // Hold a row for the first 63 hosts: alloc() gives the fake, and the
      // table hands back the name for it, which is the pair a caller has.
      const auto fake = table.alloc(name);
      CHECK(fake.has_value());
      if (fake) {
        CHECK_EQ(*fake, o);  // the fresh slots fill in order, from .1 up
        row = table.lookup(*fake);
      }
    }
    for (const auto &m : {make_v4(o, 443), make_mapped(o, 443)}) {
      const auto d = fake_connect_verdict(
          m.addr(), m.len, fake_table_answer::from_lookup(row), true);
      switch (d.verdict) {
        case fake_verdict::route_by_name:
          ++routed;
          CHECK(!d.name.empty());  // never a name-less route
          CHECK_EQ(d.name, std::string_view(name));
          break;
        case fake_verdict::refuse:
          ++refused;
          CHECK(d.name.empty());  // never a half-truth on a refusal
          break;
        case fake_verdict::passthrough:
          ++passed;
          CHECK(d.name.empty());
          CHECK(!d.addr.in_range);  // passthrough is only for non-fakes
          break;
      }
    }
  }
  CHECK(routed > 0);
  CHECK(refused > 0);
  // .0 and .255 are in range, so nothing in this sweep may pass through.
  CHECK_EQ(passed, std::size_t(0));
}

// ------------------------------------------------------------- the owner (S2)

void the_owner_is_one_object_for_the_whole_binary() {
  // The residency claim, checked: one accessor, one object, no window where it
  // is missing.  A second call through a function pointer keeps the compiler
  // from folding the two reads into one.
  fake_ip_owner &a = fake_ip_owner::instance();
  auto *through = +[] { return &fake_ip_owner::instance(); };
  fake_ip_owner *b = through();
  CHECK_EQ(&a, b);
  CHECK_EQ(a.capacity(), FAKEIP_CAPACITY);
  CHECK_EQ(a.quarantine(), FAKEIP_DEFAULT_QUARANTINE);
  CHECK_EQ(a.exclusions(), std::size_t(0));
  // The singleton is not the only usable owner: a test (or a second table,
  // if a design ever wanted one) builds its own.  Everything stateful below
  // runs against a local owner so no scenario depends on the order of another.
  fake_ip_owner local;
  CHECK_EQ(local.capacity(), FAKEIP_CAPACITY);
  CHECK(&local != b);
}

void alloc_for_answers_in_the_shape_the_recognizer_reads() {
  fake_ip_owner owner;
  const auto first = owner.alloc_for("one.example.com");
  CHECK(first.has_value());
  if (!first) {
    return;
  }
  CHECK(first->readable);
  CHECK(first->in_range);
  CHECK(first->issuable);
  CHECK_EQ(first->slot, std::size_t(0));  // the fresh rows fill from slot 0
  CHECK_EQ(first->port, std::uint16_t(0));  // a fake carries no port

  // A sockaddr built from that answer is recognised as the same fake: the
  // resolve side and the connect side hand each other one type and cannot
  // disagree about what is in range.
  const auto m = make_v4(first->v4, 443);
  const auto r = read_fake_addr(m.addr(), m.len);
  CHECK_EQ(r.slot, first->slot);
  CHECK_EQ(r.in_range, first->in_range);
  CHECK_EQ(r.issuable, first->issuable);
  CHECK_EQ(r.v4, first->v4);

  // Stable: asking twice for a live name gets the SAME address, not a second
  // one, because an application that resolves twice must not find its host in
  // two places.
  const auto again = owner.alloc_for("one.example.com");
  CHECK(again.has_value());
  CHECK_EQ(again->v4, first->v4);

  // An empty name is nothing to issue an address for.
  CHECK(!owner.alloc_for("").has_value());
}

void a_name_comes_back_owned_after_its_row_is_gone() {
  // THE OWNERSHIP RULE, as a test rather than a comment: whatever the owner
  // hands back has to survive the table destroying the row it came from.
  fake_ip_owner owner;
  const std::string name = "keep-me.example.com";
  const auto fake = owner.alloc_for(name);
  CHECK(fake.has_value());
  if (!fake) {
    return;
  }

  const auto row = owner.lookup(fake->v4);
  CHECK(row.has_value());
  CHECK_EQ(*row, name);

  // Retire the row out from under the answer: exclude() clears the row string
  // IN PLACE, so a borrowed view would now read as empty -- or worse, point at
  // a different name after a re-claim.  The copy cannot be moved by any of it.
  owner.exclude_proxy(fake->v4);
  CHECK(!owner.lookup(fake->v4).has_value());
  CHECK_EQ(*row, name);
  CHECK_EQ(row->size(), name.size());

  // And the sockaddr-shaped lookup sees the same thing, from both spellings.
  const auto m4 = make_v4(fake->v4, 443);
  const auto m6 = make_mapped(fake->v4, 443);
  CHECK(!owner.lookup(m4.addr(), m4.len).has_value());
  CHECK(!owner.lookup(m6.addr(), m6.len).has_value());
  CHECK(owner.excludes(fake->v4));
}

void pins_travel_through_the_lock_and_never_underflow() {
  fake_ip_owner owner;
  const auto fake = owner.alloc_for("pinned.example.com");
  CHECK(fake.has_value());
  if (!fake) {
    return;
  }
  CHECK_EQ(owner.pins(fake->v4), std::size_t(0));
  CHECK(owner.pin(fake->v4));
  CHECK_EQ(owner.pins(fake->v4), std::size_t(1));
  CHECK(owner.pin(fake->v4));  // a second connect to the same host
  CHECK_EQ(owner.pins(fake->v4), std::size_t(2));
  CHECK(owner.unpin(fake->v4));
  CHECK(owner.unpin(fake->v4));
  CHECK_EQ(owner.pins(fake->v4), std::size_t(0));
  // An unbalanced release is refused, not wrapped.
  CHECK(!owner.unpin(fake->v4));
  CHECK_EQ(owner.pins(fake->v4), std::size_t(0));
  // And an address the owner holds nothing for is not pinnable at all.
  CHECK(!owner.pin(REAL));
  CHECK(!owner.unpin(REAL));
  CHECK_EQ(owner.pins(REAL), std::size_t(0));
}

void note_touched_keeps_the_name_still_in_use() {
  // quarantine = 0 so the ring cannot hide the LRU effect being measured:
  // the only ordering left is the touch clock, which is what this is about.
  fake_ip_owner owner(0);
  std::vector<fake_addr_read> held;
  for (std::size_t i = 0; i < FAKEIP_CAPACITY; ++i) {
    const auto issued = owner.alloc_for(host(i));
    if (!issued) {
      ++test_failures;
      return;
    }
    held.push_back(*issued);
  }
  CHECK_EQ(owner.live_names(), FAKEIP_CAPACITY);

  // The first name is the oldest.  Touch it -- as a live connection would on
  // every connect it makes with that fake -- and the next eviction must take
  // the SECOND row instead.
  CHECK(owner.note_touched(held[0].v4));
  const auto warmed = make_v4(held[0].v4, 443);
  CHECK(owner.note_touched(warmed.addr(), warmed.len));  // the buffer form
  const auto stranger = owner.alloc_for("stranger.example.com");
  CHECK(stranger.has_value());
  if (!stranger) {
    return;
  }
  // Freed and, with a zero-length ring, re-issued in the same breath: the
  // newcomer lands on the row that was just evicted -- held[1], because
  // held[0] was touched and is no longer the least recently used.
  CHECK_EQ(stranger->v4, held[1].v4);
  // Named optionals throughout: an "auto &&" bound to *owner.lookup(...) would
  // name a string inside an optional that dies at the end of the statement.
  const auto kept = owner.lookup(held[0].v4);
  CHECK(kept.has_value());
  CHECK_EQ(*kept, host(0));  // still the name it was issued for
  const auto taken = owner.lookup(stranger->v4);
  CHECK(taken.has_value());
  CHECK_EQ(*taken, std::string("stranger.example.com"));  // not host(1)

  // Warming something that is not a row says so.
  CHECK(!owner.note_touched(REAL));
  const auto real = make_v4(REAL, 443);
  CHECK(!owner.note_touched(real.addr(), real.len));
}

void forward_progress_is_the_only_thing_that_drains_the_ring() {
  fake_ip_owner owner;  // the shipped ring length, 127 allocations
  CHECK_EQ(owner.quarantine(), FAKEIP_DEFAULT_QUARANTINE);
  for (std::size_t i = 0; i < FAKEIP_CAPACITY; ++i) {
    if (!owner.alloc_for(host(i))) {
      ++test_failures;
      return;
    }
  }

  // Full, and nothing pinned: the first attempt retires the LRU row and is
  // itself refused, because the slot it freed is in quarantine.
  CHECK(!owner.alloc_for("newcomer.example.com").has_value());
  CHECK_EQ(owner.quarantined(), std::size_t(1));
  // Idleness does not drain it.  Five more attempts advance the clock by five
  // ticks of their own -- nowhere near the ring -- and retire five more rows.
  for (int i = 0; i < 5; ++i) {
    CHECK(!owner.alloc_for("newcomer.example.com").has_value());
  }
  CHECK_EQ(owner.quarantined(), std::size_t(6));

  // The caller says time passed, and the oldest quarantine expires.  This is
  // the seam a process that stops resolving still needs: without it the ring
  // freezes at whatever the last allocation was and half the range is gone.
  owner.forward_progress(FAKEIP_DEFAULT_QUARANTINE);
  const auto after = owner.alloc_for("newcomer.example.com");
  CHECK(after.has_value());
  if (after) {
    // It lands on the row retired FIRST -- host(0) was the oldest, and the
    // scan for a claimable slot runs from index 0.
    CHECK_EQ(after->v4, fake_ip_at(0));
    const auto row = owner.lookup(after->v4);
    CHECK(row.has_value());
    CHECK_EQ(*row, std::string("newcomer.example.com"));
    // host(0) is gone: the address it used is somebody else's now, and
    // the buffer form of the lookup agrees with the octet form.
    const auto buffer = make_v4(fake_ip_at(0), 443);
    const auto by_buffer = owner.lookup(buffer.addr(), buffer.len);
    const auto by_octets = owner.lookup(fake_ip_at(0));
    CHECK(by_buffer.has_value());
    CHECK(by_octets.has_value());
    CHECK_EQ(*by_buffer, *by_octets);
    CHECK(*by_octets != host(0));
  }
  // A zero-length advance moves nothing, and the counter is the caller's to
  // read back.
  const auto before = owner.forward_progress(0);
  CHECK_EQ(owner.forward_progress(0), before);
}

void excluding_the_proxy_in_the_range_costs_exactly_one_slot() {
  fake_ip_owner owner;
  const auto fake = owner.alloc_for("loop.example.com");
  CHECK(fake.has_value());
  if (!fake) {
    return;
  }
  CHECK_EQ(owner.capacity(), FAKEIP_CAPACITY);

  // The front-end path knows the endpoint as the uint32 an IpAddr carries.
  owner.exclude_proxy(fake_ip_to_u32(fake->v4));
  CHECK(owner.excludes(fake->v4));
  CHECK_EQ(owner.exclusions(), std::size_t(1));
  CHECK_EQ(owner.capacity(), FAKEIP_CAPACITY - 1);
  // Retiring, not keeping: the row that named the proxy is gone at once.
  CHECK(!owner.lookup(fake->v4).has_value());

  // Idempotent, both spellings, however many times the endpoint is re-set.
  owner.exclude_proxy(fake->v4);
  owner.exclude_proxy(fake_ip_to_u32(fake->v4));
  CHECK_EQ(owner.exclusions(), std::size_t(1));

  // An address outside the range excludes nothing and costs nothing.
  owner.exclude_proxy(REAL);
  CHECK(!owner.excludes(REAL));
  CHECK_EQ(owner.exclusions(), std::size_t(1));
}

void decide_is_the_connect_sites_one_call() {
  fake_ip_owner owner;
  const std::string name = "site.example.com";
  const auto fake = owner.alloc_for(name);
  CHECK(fake.has_value());
  if (!fake) {
    return;
  }
  owner.pin(fake->v4);

  // A hit, in both spellings, with a proxy: route by the recovered name.
  for (const auto &m : {make_v4(fake->v4, 443), make_mapped(fake->v4, 443)}) {
    const auto d = owner.decide(m.addr(), m.len, true);
    CHECK(d.verdict == fake_verdict::route_by_name);
    CHECK_EQ(d.name, name);
    CHECK_EQ(d.addr.slot, fake->slot);
    CHECK(d.addr.in_range);
    // Owned: the string in the answer is not the row.
    CHECK(d.name.data() != owner.lookup(fake->v4)->data());
  }

  // A miss inside the range, with and without a proxy.
  const auto never = make_v4(octets{198, 51, 100, 99}, 443);
  CHECK(owner.decide(never.addr(), never.len, true).verdict ==
        fake_verdict::refuse);
  CHECK(owner.decide(never.addr(), never.len, false).verdict ==
        fake_verdict::passthrough);
  CHECK(owner.decide(never.addr(), never.len, true).name.empty());

  // A real destination: passthrough whatever the config, and no lock taken.
  const auto real = make_v4(REAL, 443);
  const auto rd = owner.decide(real.addr(), real.len, true);
  CHECK(rd.verdict == fake_verdict::passthrough);
  CHECK(rd.name.empty());

  // A buffer too short to read: not ours, so the original call runs.  This is
  // the case where a careless owner would both claim a fake and read past the
  // end of the victim's allocation.
  const auto truncated = make_truncated_v4(fake->v4, 443, 8);
  const auto td = owner.decide(truncated.addr(), truncated.len, true);
  CHECK(td.verdict == fake_verdict::passthrough);
  CHECK(!td.addr.readable);

  // The answer outlives the row: exclude the fake after deciding, and the
  // connect still has the name it was going to put on the wire.
  const auto d = owner.decide(*fake, true);  // the fake_addr_read overload
  CHECK(d.verdict == fake_verdict::route_by_name);
  owner.exclude_proxy(fake->v4);
  CHECK(!owner.lookup(fake->v4).has_value());
  CHECK_EQ(d.name, name);
  owner.unpin(fake->v4);
}

void counters_are_what_a_report_line_would_print() {
  fake_ip_owner owner;
  CHECK_EQ(owner.live_names(), std::size_t(0));
  CHECK_EQ(owner.quarantined(), std::size_t(0));
  CHECK_EQ(owner.exclusions(), std::size_t(0));
  CHECK_EQ(owner.capacity(), FAKEIP_CAPACITY);
  for (std::size_t i = 0; i < 3; ++i) {
    CHECK(owner.alloc_for(host(i)).has_value());
  }
  CHECK_EQ(owner.live_names(), std::size_t(3));
  CHECK_EQ(owner.capacity(), FAKEIP_CAPACITY);  // capacity counts exclusions
  owner.exclude_proxy(octets{198, 51, 100, 200});
  CHECK_EQ(owner.exclusions(), std::size_t(1));
  CHECK_EQ(owner.capacity(), FAKEIP_CAPACITY - 1);
  // Excluding a byte that is not a slot costs nothing.
  owner.exclude_proxy(NETWORK);
  CHECK_EQ(owner.exclusions(), std::size_t(1));
}

void one_owner_stays_consistent_under_concurrent_connects() {
  // The reason the mutex exists: a detour can be entered from several threads
  // at once, and two of them resolving the same name must not get two fakes,
  // while every answer must still name the host it was issued for.  It is also
  // the deadlock probe -- if any method re-enters the owner under its own
  // lock, this scenario hangs and the registered TIMEOUT 60 is what catches
  // it (see the S2 mutation proof).
  fake_ip_owner owner;
  constexpr int threads = 4;
  constexpr int per_thread = 25;
  std::vector<std::thread> workers;
  // Written only by the worker that owns the slot, read after every join().
  std::atomic<int> broken{0};

  for (int t = 0; t < threads; ++t) {
    workers.emplace_back([&owner, &broken, t] {
      for (int i = 0; i < per_thread; ++i) {
        const std::string name = host(std::size_t(t) * per_thread + i);
        const auto fake = owner.alloc_for(name);
        if (!fake) {
          ++broken;
          continue;
        }
        if (!owner.pin(fake->v4)) {
          ++broken;
        }
        const auto row = owner.lookup(fake->v4);
        if (!row || *row != name) {
          ++broken;  // a name that came back wrong is a misroute
        }
        const auto m = make_mapped(fake->v4, 443);
        const auto d = owner.decide(m.addr(), m.len, true);
        if (d.verdict != fake_verdict::route_by_name || d.name != name) {
          ++broken;
        }
        owner.note_touched(fake->v4);
      }
    });
  }
  for (auto &w : workers) {
    w.join();
  }

  CHECK_EQ(broken.load(), 0);
  CHECK_EQ(owner.live_names(), std::size_t(threads * per_thread));
  // 100 names out of 254 slots, every one pinned: nothing could be
  // evicted, and each name is still behind the one address it was issued for
  // -- which is the property that matters, because slots are handed out in
  // whatever order the threads raced through the lock.  A torn critical
  // section shows up as a name pointing at another name's address.
  for (std::size_t i = 0; i < std::size_t(threads * per_thread); ++i) {
    const auto issued = owner.alloc_for(host(i));  // stable for a live row
    if (!issued) {
      ++test_failures;
      std::printf("FAIL %s lost its address\n", host(i).c_str());
      break;
    }
    const auto row = owner.lookup(issued->v4);
    if (!row || *row != host(i)) {
      ++test_failures;
      std::printf("FAIL %s resolves to the wrong name\n", host(i).c_str());
      break;
    }
    if (owner.pins(issued->v4) != 1) {
      ++test_failures;
      std::printf("FAIL %s has the wrong pin count\n", host(i).c_str());
      break;
    }
  }
}

int main() {
  RUN(the_reader_only_trusts_asserted_layouts);
  RUN(a_v4_fake_is_recognised_with_its_octets_and_port);
  RUN(the_v4_mapped_spelling_is_the_same_fake);
  RUN(a_native_v6_answer_is_never_ours);
  RUN(the_reader_reads_wire_order_not_winnets_reversed_storage);
  RUN(out_of_range_neighbours_are_not_ours);
  RUN(network_and_broadcast_are_in_range_but_never_issued);
  RUN(other_families_and_missing_buffers_are_not_fakes);
  RUN(a_buffer_shorter_than_its_struct_is_never_interpreted);
  RUN(an_absurd_length_is_not_an_address_but_a_storage_is);
  RUN(a_hit_in_range_routes_by_the_recovered_name);
  RUN(an_in_range_miss_refuses_only_when_a_proxy_is_configured);
  RUN(a_miss_is_what_a_nameless_address_gets_in_both_spellings);
  RUN(nothing_outside_the_range_ever_routes_or_refuses);
  RUN(the_verdict_never_invents_a_name_it_was_not_given);
  RUN(a_verdict_is_a_pure_function_of_its_arguments);
  RUN(verdict_text_is_fixed_text_for_logs);
  RUN(the_real_table_and_a_real_sockaddr_round_trip);
  RUN(an_excluded_or_evicted_fake_falls_into_the_miss_path);
  RUN(eviction_turns_a_live_row_back_into_a_refusal);
  RUN(a_domain_shaped_verdict_is_all_the_fake_path_leaves_behind);
  RUN(the_owner_is_one_object_for_the_whole_binary);
  RUN(alloc_for_answers_in_the_shape_the_recognizer_reads);
  RUN(a_name_comes_back_owned_after_its_row_is_gone);
  RUN(pins_travel_through_the_lock_and_never_underflow);
  RUN(note_touched_keeps_the_name_still_in_use);
  RUN(forward_progress_is_the_only_thing_that_drains_the_ring);
  RUN(excluding_the_proxy_in_the_range_costs_exactly_one_slot);
  RUN(decide_is_the_connect_sites_one_call);
  RUN(counters_are_what_a_report_line_would_print);
  RUN(one_owner_stays_consistent_under_concurrent_connects);

  return test_failures;
}
