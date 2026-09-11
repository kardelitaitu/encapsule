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

#include "test_support.hpp"

#include <asio/ip/address.hpp>

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <sstream>
#include <span>
#include <string>
#include <vector>

namespace ip = asio::ip;

#include <schema.hpp>

namespace {

// The exact framing used by async_io.hpp: a length from encode_skip(), then
// message_coder::encode() into a buffer of that size.
template <typename M>
std::vector<std::byte> encode(const M &msg) {
  std::vector<std::byte> buf(
      pp::skipper<pp::message_coder<M>>::encode_skip(msg));
  pp::message_coder<M>::encode(msg, std::span(buf));
  return buf;
}

// protopuf 2.2.1 decodes without any bounds check (varint_coder::decode
// dereferences before testing the end, array_coder::decode loops on the
// length prefix), so only whole self-delimited buffers may be decoded.
// Bytes left over mean the buffer did not hold exactly one message.
template <typename M>
std::optional<M> decode(std::vector<std::byte> buf) {
  auto [msg, remains] = pp::message_coder<M>::decode(std::span(buf));
  if (!remains.empty()) {
    return std::nullopt;
  }
  return msg;
}

// pp::message::operator== is a fold expression MSVC 17.14 rejects here with
// C4716 ("must return a value"), so message equality is checked through the
// encoding instead: fields are written in declaration order and empty ones
// are skipped, so equal messages encode to equal bytes.
template <typename M>
bool same_encoding(const M &a, const M &b) {
  return encode(a) == encode(b);
}

InjecteeConnect make_connect() {
  return InjecteeConnect{
      0x1234u,
      IpAddr{0x7F000001u, {}, {}, 1080u},
      IpAddr{{}, {}, std::string("proxy.example.com"), 1081u},
      std::string("connect")};
}

// (1) IpAddr construction and equality: v4, v6, domain, each with a port.
void ipaddr_fields() {
  const IpAddr v4{0x0A000001u, {}, {}, 80u};
  CHECK(v4["v4_addr"_f].has_value());
  CHECK_EQ(*v4["v4_addr"_f], 0x0A000001u);
  CHECK_EQ(*v4["port"_f], 80u);
  CHECK(!v4["v6_addr"_f].has_value());
  CHECK(!v4["domain"_f].has_value());

  const std::vector<unsigned char> v6bytes(16u, 0xFEu);
  const IpAddr v6{{}, v6bytes, {}, 443u};
  CHECK(v6["v6_addr"_f].has_value());
  CHECK_EQ(v6["v6_addr"_f]->size(), static_cast<std::size_t>(16));
  CHECK(!v6["v4_addr"_f].has_value());
  CHECK_EQ(*v6["port"_f], 443u);

  const IpAddr domain{{}, {}, std::string("example.com"), 8080u};
  CHECK(domain["domain"_f].has_value());
  CHECK_EQ(*domain["domain"_f], std::string("example.com"));
  CHECK_EQ(*domain["port"_f], 8080u);
  CHECK(!domain["v4_addr"_f].has_value());

  // equality over the whole message (through the encoding, see above)
  const IpAddr same{0x0A000001u, {}, {}, 80u};
  const IpAddr other_port{0x0A000001u, {}, {}, 81u};
  const IpAddr other_addr{0x0A000002u, {}, {}, 80u};
  const IpAddr empty{};
  CHECK(same_encoding(v4, same));
  CHECK(!same_encoding(v4, other_port));
  CHECK(!same_encoding(v4, other_addr));
  CHECK(!same_encoding(v4, domain));
  CHECK(!same_encoding(v4, empty));
  CHECK(same_encoding(empty, IpAddr{}));
  // the three address arms are mutually exclusive in practice
  CHECK(!same_encoding(v4, v6));
  CHECK(!same_encoding(v6, domain));
}

// (2) encode/decode round-trips through the protopuf message coder.
void injectee_message_roundtrip() {
  const InjecteeMessage msg =
      create_message<InjecteeMessage, "connect">(make_connect());
  const auto bytes = encode(msg);
  CHECK(!bytes.empty());

  const auto back = decode<InjecteeMessage>(bytes);
  CHECK(back.has_value());
  if (!back) {
    return;
  }

  CHECK(same_encoding(msg, *back));
  CHECK_EQ((*back)["opcode"_f].value_or(std::string()),
           std::string("connect"));
  const auto &conn = (*back)["connect"_f];
  CHECK(conn.has_value());
  if (conn) {
    CHECK_EQ((*conn)["handle"_f].value_or(0u), 0x1234u);
    CHECK_EQ((*conn)["syscall"_f].value_or(std::string()),
             std::string("connect"));
    const auto &addr = (*conn)["addr"_f];
    CHECK(addr.has_value());
    if (addr) {
      CHECK_EQ(*(*addr)["v4_addr"_f], 0x7F000001u);
      CHECK_EQ(*(*addr)["port"_f], 1080u);
    }
    const auto &proxy = (*conn)["proxy"_f];
    CHECK(proxy.has_value());
    if (proxy) {
      CHECK_EQ(*(*proxy)["domain"_f], std::string("proxy.example.com"));
      CHECK_EQ(*(*proxy)["port"_f], 1081u);
    }
  }

  // the scalar arms of the payload survive too
  const InjecteeMessage pid = create_message<InjecteeMessage, "pid">(42u);
  const auto pid_back = decode<InjecteeMessage>(encode(pid));
  CHECK(pid_back.has_value());
  if (pid_back) {
    CHECK(same_encoding(pid, *pid_back));
    CHECK_EQ((*pid_back)["pid"_f].value_or(0u), 42u);
    CHECK(!(*pid_back)["connect"_f].has_value());
  }
}

void injector_message_roundtrip() {
  const InjectorConfig cfg{IpAddr{0x7F000001u, {}, {}, 9000u}, true, false};
  const InjectorMessage msg = create_message<InjectorMessage, "config">(cfg);
  const auto back = decode<InjectorMessage>(encode(msg));
  CHECK(back.has_value());
  if (!back) {
    return;
  }

  CHECK(same_encoding(msg, *back));
  CHECK_EQ((*back)["opcode"_f].value_or(std::string()), std::string("config"));
  const auto &dec = (*back)["config"_f];
  CHECK(dec.has_value());
  if (dec) {
    CHECK((*dec)["log"_f].value_or(false));
    CHECK(!(*dec)["subprocess"_f].value_or(true));
    const auto &addr = (*dec)["addr"_f];
    CHECK(addr.has_value());
    if (addr) {
      CHECK_EQ(*(*addr)["v4_addr"_f], 0x7F000001u);
      CHECK_EQ(*(*addr)["port"_f], 9000u);
    }
  }

  // encoding is deterministic: the same message yields the same bytes
  CHECK(encode(msg) == encode(*back));
}

// (3) create_message / compare_message: a matching opcode yields the payload,
// any other opcode yields std::nullopt.
void create_and_compare() {
  const InjecteeMessage msg =
      create_message<InjecteeMessage, "connect">(make_connect());
  CHECK_EQ(msg["opcode"_f].value_or(std::string()), std::string("connect"));
  CHECK(msg["pid"_f].has_value() == false);

  const auto hit = compare_message<"connect">(msg);
  CHECK(hit.has_value());
  if (hit) {
    CHECK_EQ((*hit)["handle"_f].value_or(0u), 0x1234u);
    CHECK(same_encoding(*hit, *msg["connect"_f]));
  }

  // opcode mismatch: nothing is returned, the payload is not even looked at
  const auto miss = compare_message<"pid">(msg);
  CHECK(!miss.has_value());
  CHECK(!static_cast<bool>(miss));

  const InjecteeMessage other = create_message<InjecteeMessage, "subpid">(7u);
  CHECK_EQ(compare_message<"subpid">(other).value_or(0u), 7u);
  CHECK(!compare_message<"connect">(other).has_value());
  CHECK(!compare_message<"subpid">(msg).has_value());

  const InjectorMessage imsg = create_message<InjectorMessage, "config">(
      InjectorConfig{IpAddr{{}, {}, std::string("h"), 1u}, false, true});
  const auto icfg = compare_message<"config">(imsg);
  CHECK(icfg.has_value());
  if (icfg) {
    CHECK((*icfg)["subprocess"_f].value_or(false));
    CHECK(!(*icfg)["log"_f].value_or(true));
  }
  CHECK(!compare_message<"opcode">(imsg).has_value());
}

// (4) to_asio / from_asio symmetry for v4 and v6, plus domain passthrough.
void asio_symmetry() {
  const ip::address v4 = ip::make_address("192.168.123.4");
  const IpAddr wire_v4 = from_asio(v4, 1080);
  CHECK(wire_v4["v4_addr"_f].has_value());
  CHECK(!wire_v4["v6_addr"_f].has_value());
  CHECK_EQ(*wire_v4["v4_addr"_f], v4.to_v4().to_uint());
  const auto [v4str, v4port] = to_asio(wire_v4);
  CHECK_EQ(v4str, std::string("192.168.123.4"));
  CHECK_EQ(static_cast<int>(v4port), 1080);
  CHECK(same_encoding(from_asio(ip::make_address(v4str), v4port), wire_v4));

  const ip::address v6 = ip::make_address("fe80::1:2:3");
  const IpAddr wire_v6 = from_asio(v6, 443);
  CHECK(wire_v6["v6_addr"_f].has_value());
  CHECK(!wire_v6["v4_addr"_f].has_value());
  CHECK_EQ(wire_v6["v6_addr"_f]->size(), static_cast<std::size_t>(16));
  const auto [v6str, v6port] = to_asio(wire_v6);
  CHECK_EQ(v6str, std::string("fe80::1:2:3"));
  CHECK_EQ(static_cast<int>(v6port), 443);
  CHECK(same_encoding(from_asio(ip::make_address(v6str), v6port), wire_v6));

  // v4 and v6 must not collide on the wire
  CHECK(!same_encoding(wire_v4, wire_v6));

  // a domain is not an asio::address: it round-trips as a string only
  const IpAddr wire_domain{{}, {}, std::string("example.org"), 80u};
  const auto [dstr, dport] = to_asio(wire_domain);
  CHECK_EQ(dstr, std::string("example.org"));
  CHECK_EQ(static_cast<int>(dport), 80);

  std::ostringstream os;
  os << wire_v4;
  CHECK_EQ(os.str(), std::string("192.168.123.4:1080"));
}

// (5) an incomplete buffer must not crash and must not look like a full one.
void truncated_buffer() {
  // a buffer carrying only a leading subset of the fields: the rest stay
  // unset instead of being fabricated
  const InjecteeMessage full =
      create_message<InjecteeMessage, "connect">(make_connect());
  const InjecteeMessage head{std::string("connect"), {}, {}, {}};
  const auto head_bytes = encode(head);
  const auto full_bytes = encode(full);
  CHECK(head_bytes.size() < full_bytes.size());
  CHECK(std::equal(head_bytes.begin(), head_bytes.end(), full_bytes.begin()));

  const auto back = decode<InjecteeMessage>(head_bytes);
  CHECK(back.has_value());
  if (back) {
    CHECK_EQ((*back)["opcode"_f].value_or(std::string()),
             std::string("connect"));
    CHECK(!(*back)["connect"_f].has_value());
    CHECK(!(*back)["pid"_f].has_value());
    // compare_message on a field the buffer never carried -> nullopt
    CHECK(!compare_message<"connect">(*back).has_value());
    CHECK(!same_encoding(*back, full));
  }

  // an empty buffer decodes to an empty message, it is not an error
  const auto empty = decode<InjecteeMessage>(std::vector<std::byte>{});
  CHECK(empty.has_value());
  if (empty) {
    CHECK(!(*empty)["opcode"_f].has_value());
    CHECK(!compare_message<"connect">(*empty).has_value());
  }

  // a trailing field this schema does not know is skipped, not mistaken for
  // part of the message: the known fields still decode exactly
  std::vector<std::byte> extra = full_bytes;
  extra.push_back(std::byte{0x78}); // field 15, varint: unknown here
  extra.push_back(std::byte{0x01});
  auto [msg, remains] =
      pp::message_coder<InjecteeMessage>::decode(std::span(extra));
  CHECK(msg["connect"_f].has_value());
  CHECK(remains.empty());
  CHECK(same_encoding(msg, full));
}

} // namespace

int main() {
  RUN(ipaddr_fields);
  RUN(injectee_message_roundtrip);
  RUN(injector_message_roundtrip);
  RUN(create_and_compare);
  RUN(asio_symmetry);
  RUN(truncated_buffer);
  return test_failures;
}
