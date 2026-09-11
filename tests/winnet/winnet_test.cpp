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

// Tests for src/injectee/winnet.hpp.
//
// NOTE: winnet.hpp defines its helpers at namespace scope WITHOUT `inline`,
// so this header may be included by exactly ONE translation unit or the link
// fails with LNK2005. This file is that TU.
//
// These tests LOCK the current behavior of the IPv6 conversion, including the
// reversed byte order (see the `// P4-1: revisit byte order` markers). They
// are regression pins, not endorsements: when P4-1 changes the byte order,
// these expectations are exactly what must be updated deliberately.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <WinSock2.h>
#include <Windows.h>

#include <asio/ip/address.hpp>

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <vector>

namespace ip = asio::ip;

#include <schema.hpp>
#include <winnet.hpp>

#include "test_support.hpp"

namespace {

// An address given in host byte order, e.g. 0x7f000001 == 127.0.0.1.
sockaddr_in make_v4(std::uint32_t host_order_addr, std::uint16_t port) {
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(host_order_addr);
  sa.sin_port = htons(port);
  return sa;
}

// `wire` is the address in network (wire) byte order, i.e. what a
// sockaddr_in6 really carries: {0x20, 0x01, 0x0d, 0xb8, ...} == 2001:db8::...
sockaddr_in6 make_v6(const std::array<unsigned char, 16> &wire,
                     std::uint16_t port) {
  sockaddr_in6 sa{};
  sa.sin6_family = AF_INET6;
  std::memcpy(&sa.sin6_addr, wire.data(), 16);
  sa.sin6_port = htons(port);
  return sa;
}

std::array<unsigned char, 16> v6_bytes(const sockaddr *sa) {
  return std::bit_cast<std::array<unsigned char, 16>>(
      ((const sockaddr_in6 *)sa)->sin6_addr);
}

const sockaddr *as_sockaddr(const sockaddr_in *sa) {
  return (const sockaddr *)sa;
}
const sockaddr *as_sockaddr(const sockaddr_in6 *sa) {
  return (const sockaddr *)sa;
}

// 2001:db8::1 on the wire.
constexpr std::array<unsigned char, 16> k2001db8_1{
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

// What to_ip_addr currently stores for k2001db8_1: the wire bytes REVERSED.
// P4-1: revisit byte order (winnet.hpp:33 builds the vector from
// addr.rbegin()/addr.rend()).
constexpr std::array<unsigned char, 16> k2001db8_1_current_storage{
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xb8, 0x0d, 0x01, 0x20};

constexpr std::array<unsigned char, 16> kloopback6{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

} // namespace

// ---------------------------------------------------------------- to_ip_addr

void to_ip_addr_v4_reads_host_order() {
  const auto sa = make_v4(0x7f000001u, 8080); // 127.0.0.1:8080
  const auto msg = to_ip_addr(as_sockaddr(&sa));

  CHECK(msg.has_value());
  CHECK_EQ((*msg)["v4_addr"_f].value(), 0x7f000001u); // ntohl'ed -> host order
  CHECK_EQ((*msg)["port"_f].value(), 8080u);          // ntohs'ed -> host order
  CHECK(!(*msg)["v6_addr"_f].has_value());
  CHECK(!(*msg)["domain"_f].has_value());

  const auto sa2 = make_v4(0x0a0000feu, 1); // 10.0.0.254
  CHECK_EQ((*to_ip_addr(as_sockaddr(&sa2)))["v4_addr"_f].value(), 0x0a0000feu);
}

void to_ip_addr_v6_stores_reversed_bytes() {
  const auto sa = make_v6(k2001db8_1, 4433);
  const auto msg = to_ip_addr(as_sockaddr(&sa));

  CHECK(msg.has_value());
  CHECK(!(*msg)["v4_addr"_f].has_value());
  CHECK_EQ((*msg)["port"_f].value(), 4433u);

  const auto &stored = (*msg)["v6_addr"_f].value();
  CHECK_EQ(stored.size(), 16u);
  // P4-1: revisit byte order -- locks the reversed layout on purpose.
  CHECK(std::equal(stored.begin(), stored.end(),
                   k2001db8_1_current_storage.begin()));
}

void to_ip_addr_rejects_other_families() {
  sockaddr unspec{};
  unspec.sa_family = AF_UNSPEC;
  CHECK(!to_ip_addr(&unspec).has_value());

  sockaddr unix_sa{};
  unix_sa.sa_family = AF_UNIX;
  CHECK(!to_ip_addr(&unix_sa).has_value());
}

// ---------------------------------------------------------------- to_sockaddr

void to_sockaddr_v4_writes_network_order() {
  const IpAddr msg{0x08080808u, {}, {}, 53u}; // 8.8.8.8:53
  auto [sa, len] = to_sockaddr(msg);

  CHECK(sa != nullptr);
  CHECK_EQ(len, sizeof(sockaddr_in));
  CHECK_EQ(sa->sa_family, AF_INET);

  const auto *v4 = (const sockaddr_in *)sa.get();
  CHECK_EQ(v4->sin_addr.s_addr, htonl(0x08080808u));
  CHECK_EQ(v4->sin_port, htons(53));
}

void to_sockaddr_v6_reverses_back_to_wire_order() {
  const std::vector<unsigned char> stored{k2001db8_1_current_storage.begin(),
                                          k2001db8_1_current_storage.end()};
  const IpAddr msg{{}, stored, {}, 4433u};
  auto [sa, len] = to_sockaddr(msg);

  CHECK(sa != nullptr);
  CHECK_EQ(len, sizeof(sockaddr_in6));
  CHECK_EQ(sa->sa_family, AF_INET6);
  CHECK_EQ(((const sockaddr_in6 *)sa.get())->sin6_port, htons(4433));

  // P4-1: revisit byte order -- to_sockaddr (winnet.hpp:51-52) copies into
  // arr.rbegin(), i.e. it reverses again, so the sockaddr ends up in the
  // original wire order. The two reversals cancel out; that is the invariant
  // the round-trip tests pin.
  CHECK(v6_bytes(sa.get()) == k2001db8_1);
}

// --------------------------------------------------------------- round trips

void roundtrip_v4_is_identity() {
  const auto original = make_v4(0x7f000001u, 8080);
  const auto msg = to_ip_addr(as_sockaddr(&original));
  CHECK(msg.has_value());

  auto [back, len] = to_sockaddr(*msg);
  CHECK_EQ(len, sizeof(sockaddr_in));
  const auto *v4 = (const sockaddr_in *)back.get();
  CHECK_EQ(v4->sin_addr.s_addr, original.sin_addr.s_addr);
  CHECK_EQ(v4->sin_port, original.sin_port);

  // A second trip through to_ip_addr yields the same IpAddr fields.
  const auto msg2 = to_ip_addr(back.get());
  CHECK(msg2.has_value());
  CHECK_EQ((*msg2)["v4_addr"_f].value(), (*msg)["v4_addr"_f].value());
  CHECK_EQ((*msg2)["port"_f].value(), (*msg)["port"_f].value());
}

void roundtrip_v6_is_identity() {
  const auto original = make_v6(k2001db8_1, 4433);
  const auto msg = to_ip_addr(as_sockaddr(&original));
  CHECK(msg.has_value());

  auto [back, len] = to_sockaddr(*msg);
  CHECK_EQ(len, sizeof(sockaddr_in6));
  CHECK(v6_bytes(back.get()) == k2001db8_1);
  CHECK_EQ(((const sockaddr_in6 *)back.get())->sin6_port, original.sin6_port);

  // P4-1: revisit byte order -- the IpAddr in between holds reversed bytes,
  // yet sockaddr -> IpAddr -> sockaddr is still the identity.
  const auto msg2 = to_ip_addr(back.get());
  CHECK(msg2.has_value());
  CHECK((*msg2)["v6_addr"_f].value() == (*msg)["v6_addr"_f].value());
  CHECK_EQ((*msg2)["port"_f].value(), (*msg)["port"_f].value());

  CHECK(sockequal(as_sockaddr(&original), back.get()));
}

void roundtrip_v6_loopback_and_all_ones() {
  const std::array<unsigned char, 16> all_ones{
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

  for (const auto &wire : {kloopback6, all_ones}) {
    const auto sa = make_v6(wire, 1);
    const auto msg = to_ip_addr(as_sockaddr(&sa));
    CHECK(msg.has_value());

    auto [back, len] = to_sockaddr(*msg);
    CHECK_EQ(len, sizeof(sockaddr_in6));
    CHECK(v6_bytes(back.get()) == wire);
    CHECK(sockequal(as_sockaddr(&sa), back.get()));
  }
}

// -------------------------------------------------------------- is_localhost

void is_localhost_v4_matches_127_prefix() {
  const auto a = make_v4(0x7f000001u, 1); // 127.0.0.1
  const auto b = make_v4(0x7f123456u, 1); // 127.18.52.86
  const auto c = make_v4(0x7fffffffu, 1); // 127.255.255.255
  CHECK(is_localhost(as_sockaddr(&a)));
  CHECK(is_localhost(as_sockaddr(&b)));
  CHECK(is_localhost(as_sockaddr(&c)));

  const auto d = make_v4(0x0100007fu, 1); // 1.0.0.127: last, not first octet
  const auto e = make_v4(0x08080808u, 53);
  const auto f = make_v4(0x00000000u, 0);
  CHECK(!is_localhost(as_sockaddr(&d)));
  CHECK(!is_localhost(as_sockaddr(&e)));
  CHECK(!is_localhost(as_sockaddr(&f)));
}

void is_localhost_v6_matches_loopback() {
  const std::array<unsigned char, 16> loopback2{
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
  const std::array<unsigned char, 16> loopback_0100{
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}; // ::0100
  const std::array<unsigned char, 16> unspecified{};
  const std::array<unsigned char, 16> v4mapped_loopback{
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1};
  const auto a = make_v6(kloopback6, 1);
  const auto b = make_v6(loopback2, 1);
  const auto c = make_v6(loopback_0100, 1);
  const auto d = make_v6(unspecified, 1);
  const auto e = make_v6(v4mapped_loopback, 1);
  const auto f = make_v6(k2001db8_1, 1);

  CHECK(is_localhost(as_sockaddr(&a)));
  CHECK(!is_localhost(as_sockaddr(&b)));
  CHECK(!is_localhost(as_sockaddr(&c)));
  CHECK(!is_localhost(as_sockaddr(&d)));
  // ::ffff:127.0.0.1 is not ::1, so the byte-wise test says no.
  CHECK(!is_localhost(as_sockaddr(&e)));
  CHECK(!is_localhost(as_sockaddr(&f)));
}

void is_localhost_rejects_other_families() {
  sockaddr unspec{};
  unspec.sa_family = AF_UNSPEC;
  CHECK(!is_localhost(&unspec));

  sockaddr unix_sa{};
  unix_sa.sa_family = AF_UNIX;
  CHECK(!is_localhost(&unix_sa));
}

// ------------------------------------------------------------------- is_inet

void is_inet_accepts_v4_and_v6() {
  const auto v4 = make_v4(0x7f000001u, 80);
  const auto v6 = make_v6(kloopback6, 80);
  CHECK(is_inet(as_sockaddr(&v4)));
  CHECK(is_inet(as_sockaddr(&v6)));

  sockaddr unspec{};
  unspec.sa_family = AF_UNSPEC;
  CHECK(!is_inet(&unspec));

  sockaddr unix_sa{};
  unix_sa.sa_family = AF_UNIX;
  CHECK(!is_inet(&unix_sa));
}

// ----------------------------------------------------------------- sockequal

void sockequal_v4_same_and_different() {
  const auto a = make_v4(0x7f000001u, 8080);
  const auto same = make_v4(0x7f000001u, 8080);
  const auto other_port = make_v4(0x7f000001u, 8081);
  const auto other_addr = make_v4(0x7f000002u, 8080);

  CHECK(sockequal(as_sockaddr(&a), as_sockaddr(&same)));
  CHECK(sockequal(as_sockaddr(&same), as_sockaddr(&a)));
  CHECK(!sockequal(as_sockaddr(&a), as_sockaddr(&other_port)));
  CHECK(!sockequal(as_sockaddr(&a), as_sockaddr(&other_addr)));
}

void sockequal_v6_same_and_different() {
  const auto a = make_v6(k2001db8_1, 4433);
  const auto same = make_v6(k2001db8_1, 4433);
  const auto other_port = make_v6(k2001db8_1, 4434);
  const std::array<unsigned char, 16> last_byte_diff = [] {
    auto copy = k2001db8_1;
    copy[15] = 0x02; // 2001:db8::2
    return copy;
  }();
  const std::array<unsigned char, 16> first_byte_diff = [] {
    auto copy = k2001db8_1;
    copy[0] = 0x21; // 2101:db8::1
    return copy;
  }();
  const auto b = make_v6(last_byte_diff, 4433);
  const auto c = make_v6(first_byte_diff, 4433);

  CHECK(sockequal(as_sockaddr(&a), as_sockaddr(&same)));
  CHECK(!sockequal(as_sockaddr(&a), as_sockaddr(&other_port)));
  CHECK(!sockequal(as_sockaddr(&a), as_sockaddr(&b)));
  // All 16 bytes participate, not just the trailing ones.
  CHECK(!sockequal(as_sockaddr(&a), as_sockaddr(&c)));
}

void sockequal_different_family_is_false() {
  const auto v4 = make_v4(0x7f000001u, 8080);
  const auto v6 = make_v6(kloopback6, 8080);

  CHECK(!sockequal(as_sockaddr(&v4), as_sockaddr(&v6)));
  CHECK(!sockequal(as_sockaddr(&v6), as_sockaddr(&v4)));

  sockaddr unspec{};
  unspec.sa_family = AF_UNSPEC;
  CHECK(!sockequal(&unspec, as_sockaddr(&v4)));
  CHECK(!sockequal(as_sockaddr(&v4), &unspec));
  CHECK(!sockequal(&unspec, as_sockaddr(&v6)));
}

void sockequal_same_unsupported_family_is_false() {
  // Locks current behavior: two identical AF_UNSPEC addresses are NOT equal,
  // because the family-matched branch falls through to `return false`
  // (winnet.hpp:98, "FIXME: add equal checking for more family"). Fixing it
  // is P4 scope, so this pin stays as-is.
  sockaddr a{};
  a.sa_family = AF_UNSPEC;
  sockaddr b{};
  b.sa_family = AF_UNSPEC;

  CHECK(!is_inet(&a));
  CHECK(!sockequal(&a, &b));
}

int main() {
  WSADATA wsa{};
  const int err = WSAStartup(MAKEWORD(2, 2), &wsa);
  if (err != 0) {
    std::printf("FAIL WSAStartup: %d\n", err);
    return 1;
  }

  RUN(to_ip_addr_v4_reads_host_order);
  RUN(to_ip_addr_v6_stores_reversed_bytes);
  RUN(to_ip_addr_rejects_other_families);
  RUN(to_sockaddr_v4_writes_network_order);
  RUN(to_sockaddr_v6_reverses_back_to_wire_order);
  RUN(roundtrip_v4_is_identity);
  RUN(roundtrip_v6_is_identity);
  RUN(roundtrip_v6_loopback_and_all_ones);
  RUN(is_localhost_v4_matches_127_prefix);
  RUN(is_localhost_v6_matches_loopback);
  RUN(is_localhost_rejects_other_families);
  RUN(is_inet_accepts_v4_and_v6);
  RUN(sockequal_v4_same_and_different);
  RUN(sockequal_v6_same_and_different);
  RUN(sockequal_different_family_is_false);
  RUN(sockequal_same_unsupported_family_is_false);

  WSACleanup();
  return test_failures;
}
