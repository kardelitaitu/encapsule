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

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <WinSock2.h>
#include <Windows.h>

#include "test_support.hpp"

#include <asio/ip/address.hpp>

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <sstream>
#include <span>
#include <string>
#include <vector>

namespace ip = asio::ip;

#include <schema.hpp>
#include <utils.hpp>

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
  // No credentials set: fields 4/5 stay absent (the P5 wire-compat case).
  const InjectorConfig cfg{IpAddr{0x7F000001u, {}, {}, 9000u}, true, false,
                           {}, {}};
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
    // the wire carried no fields 4/5, so nothing was fabricated on decode
    CHECK(!(*dec)["username"_f].has_value());
    CHECK(!(*dec)["password"_f].has_value());
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

  const InjectorConfig plain{IpAddr{{}, {}, std::string("h"), 1u}, false,
                             true, {}, {}};
  const InjectorMessage imsg =
      create_message<InjectorMessage, "config">(plain);
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
  const InjecteeMessage head{std::string("connect"), {}, {}, {}, {}};
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

// (6) the per-injection token field (P4-3): it round-trips byte-exactly,
// stays absent when unset, and a different token is a different message.
void injectee_token_field() {
  const std::vector<unsigned char> token{0x01u, 0x23u, 0x45u, 0x67u,
                                         0x89u, 0xabu, 0xcdu, 0xefu};

  InjecteeMessage msg = create_message<InjecteeMessage, "pid">(42u);
  CHECK(!msg["token"_f].has_value()); // the token is opt-in per message
  msg["token"_f] = token;

  const auto bytes = encode(msg);
  const auto back = decode<InjecteeMessage>(bytes);
  CHECK(back.has_value());
  if (!back) {
    return;
  }
  CHECK(same_encoding(msg, *back));

  const auto &got = (*back)["token"_f];
  CHECK(got.has_value());
  if (got) {
    CHECK_EQ(got->size(), token.size());
    CHECK(std::equal(token.begin(), token.end(), got->begin()));
  }

  // wire format is pinned too: field 5, length-delimited (wire type 2)
  // -> tag 0x2a, then an 8-byte length prefix, then the token itself.
  InjecteeMessage token_only;
  token_only["token"_f] = token;
  const auto only = encode(token_only);
  CHECK_EQ(only.size(), token.size() + 2);
  if (only.size() == token.size() + 2) {
    CHECK(only[0] == std::byte{0x2a});
    CHECK(only[1] == std::byte{0x08});
    CHECK(std::equal(token.begin(), token.end(), only.begin() + 2,
                     [](unsigned char a, std::byte b) {
                       return a == static_cast<unsigned char>(b);
                     }));
  }

  // one flipped byte is a different token, not an equal message
  InjecteeMessage other = msg;
  (*other["token"_f])[0] = 0x02u;
  CHECK(!same_encoding(msg, other));
  CHECK(encode(msg) != encode(other));
}

// (7) the mapping payload contract (P4-3): the layout both sides copy
// byte-for-byte through the shared mapping, plus the token it carries.
void mapping_payload_layout() {
  CHECK_EQ(port_mapping_token_size, static_cast<std::size_t>(8));
  CHECK_EQ(get_port_mapping_payload_size(), sizeof(port_mapping_payload));
  CHECK_EQ(get_port_mapping_payload_size(),
           sizeof(std::uint16_t) + port_mapping_token_size);
  // no padding surprises: port first, token right after it
  CHECK_EQ(offsetof(port_mapping_payload, port), static_cast<std::size_t>(0));
  CHECK_EQ(offsetof(port_mapping_payload, token), sizeof(std::uint16_t));

  const auto payload = get_port_mapping_payload(1080);
  CHECK(payload.has_value());
  if (!payload) {
    return;
  }
  CHECK_EQ(static_cast<int>(payload->port), 1080);

  const auto again = get_port_mapping_payload(1080);
  CHECK(again.has_value());
  if (again) {
    // two injections never share a token (2^-64 collision aside)
    CHECK(std::memcmp(payload->token, again->token,
                      port_mapping_token_size) != 0);
  }

  // the mapping name contract is untouched by the payload change
  const auto name = get_port_mapping_name(4242);
  CHECK(name.find(port_mapping_name) == 0);
  CHECK(name.ends_with(L"4242"));
}

// (8) the P5 credential fields (P5 #1): InjectorConfig grew "username" (4)
// and "password" (5).  Both are optional, both round-trip byte-exactly, an
// absent one encodes NOTHING, and a credential-free config still encodes to
// exactly the pre-P5 bytes -- an old injector has to keep talking to a new
// injectee and the other way round.  The field numbers ARE the contract, so
// they are pinned as wire tags: 4 and 5, both length-delimited.

// InjectorConfig exactly as it stood before P5 #1, declared here (never in the
// product header) so the credential-free encoding is compared against REAL
// pre-P5 bytes and not against another message of today's schema.
using InjectorConfigV1 =
    pp::message<pp::message_field<"addr", 1, IpAddr>, pp::bool_field<"log", 2>,
                pp::bool_field<"subprocess", 3>>;

constexpr std::uint8_t kUsernameTag = 0x22;  // (4 << 3) | LEN
constexpr std::uint8_t kPasswordTag = 0x2a;  // (5 << 3) | LEN

// One length-delimited field as it goes on the wire, for a value below 128
// bytes (so the LEN prefix is a single varint octet).
std::vector<std::byte> delimited_field(std::uint8_t tag,
                                       const std::string &value) {
  std::vector<std::byte> out;
  out.push_back(static_cast<std::byte>(tag));
  out.push_back(static_cast<std::byte>(value.size()));
  for (const char c : value) {
    out.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
  }
  return out;
}

void append(std::vector<std::byte> &dst, const std::vector<std::byte> &src) {
  dst.insert(dst.end(), src.begin(), src.end());
}

bool contains(const std::vector<std::byte> &hay, const std::string &needle) {
  const auto hit = std::search(
      hay.begin(), hay.end(), needle.begin(), needle.end(),
      [](std::byte h, char n) {
        return static_cast<unsigned char>(h) ==
               static_cast<unsigned char>(n);
      });
  return hit != hay.end();
}

// The same proxy address with, or without, each credential.  A missing
// credential is ABSENT -- std::nullopt -- never an empty string, because the
// contract says absent is what "no authentication offered" means on the wire.
InjectorConfig make_config(
    const std::optional<std::string> &user = std::nullopt,
    const std::optional<std::string> &pass = std::nullopt) {
  InjectorConfig cfg{
      IpAddr{{}, {}, std::string("proxy.example.com"), 1080u}, true, false, {},
      {}};
  if (user) {
    cfg["username"_f] = *user;
  }
  if (pass) {
    cfg["password"_f] = *pass;
  }
  return cfg;
}

void injector_config_credentials_round_trip() {
  const InjectorConfig cfg = make_config("alice", "s3cr3t!");
  const auto bytes = encode(cfg);

  const auto back = decode<InjectorConfig>(bytes);
  CHECK(back.has_value());
  if (back) {
    CHECK(same_encoding(cfg, *back));
    CHECK(encode(cfg) == encode(*back));  // byte-equality, not just equal
    CHECK_EQ(*(*back)["username"_f], std::string("alice"));
    CHECK_EQ(*(*back)["password"_f], std::string("s3cr3t!"));
  }

  // They survive the transport that is actually used too: InjectorMessage
  // wraps the config and compare_message<"config"> hands it to the injectee.
  const InjectorMessage msg = create_message<InjectorMessage, "config">(cfg);
  const auto wrapped = decode<InjectorMessage>(encode(msg));
  CHECK(wrapped.has_value());
  if (wrapped) {
    const auto forwarded = compare_message<"config">(*wrapped);
    CHECK(forwarded.has_value());
    if (forwarded) {
      CHECK(same_encoding(*forwarded, cfg));
      CHECK_EQ(*(*forwarded)["username"_f], std::string("alice"));
      CHECK_EQ(*(*forwarded)["password"_f], std::string("s3cr3t!"));
    }
  }

  // Wire layout: the two fields are APPENDED after the pre-P5 bytes, tagged
  // with their contract field numbers, username first.
  const auto no_creds = encode(make_config());
  std::vector<std::byte> tail;
  append(tail, delimited_field(kUsernameTag, "alice"));
  append(tail, delimited_field(kPasswordTag, "s3cr3t!"));
  CHECK_EQ(bytes.size(), no_creds.size() + tail.size());
  CHECK(std::equal(no_creds.begin(), no_creds.end(), bytes.begin()));
  CHECK(std::equal(tail.begin(), tail.end(),
                   bytes.begin() + no_creds.size()));
}

// The wire-compat pin: take the credentials away and the message is
// byte-for-byte what encapsule put on the wire before P5 existed.
void injector_config_without_credentials_is_wire_identical() {
  const InjectorConfigV1 v1{
      IpAddr{{}, {}, std::string("proxy.example.com"), 1080u}, true, false};
  const InjectorConfig v2 = make_config();

  CHECK(encode(v1) == encode(v2));

  // The style the product code really uses -- default-construct, then assign
  // the fields it knows -- leaves 4/5 absent too, and lands on the same bytes.
  InjectorConfig assigned;
  assigned["addr"_f] =
      IpAddr{{}, {}, std::string("proxy.example.com"), 1080u};
  assigned["log"_f] = true;
  assigned["subprocess"_f] = false;
  CHECK(encode(v1) == encode(assigned));
  CHECK(!encode(assigned).empty());

  // New reader, old bytes: fields 4/5 stay ABSENT, the contract's "no
  // authentication offered"; nothing is fabricated on the way in.
  const auto upgraded = decode<InjectorConfig>(encode(v1));
  CHECK(upgraded.has_value());
  if (upgraded) {
    CHECK(!(*upgraded)["username"_f].has_value());
    CHECK(!(*upgraded)["password"_f].has_value());
    CHECK((*upgraded)["log"_f].value_or(false));
    CHECK(!(*upgraded)["subprocess"_f].value_or(true));
    const auto &addr = (*upgraded)["addr"_f];
    CHECK(addr.has_value());
    if (addr) {
      CHECK_EQ(*(*addr)["domain"_f], std::string("proxy.example.com"));
      CHECK_EQ(*(*addr)["port"_f], 1080u);
    }
  }

  // Old reader, new bytes: the unknown fields 4/5 are skipped, not fatal, and
  // the pre-P5 view of the message holds no trace of them.
  const auto downgraded =
      decode<InjectorConfigV1>(encode(make_config("alice", "s3cr3t!")));
  CHECK(downgraded.has_value());
  if (downgraded) {
    CHECK(encode(*downgraded) == encode(v1));
  }
}

// Username and password are separate fields, so either can travel alone.  That
// is what lets a log line or a GUI row redact one and still show the other.
void injector_config_credential_fields_are_independent() {
  const InjectorConfig user_only = make_config("anon");
  const InjectorConfig pass_only = make_config(std::nullopt, "pw");
  const InjectorConfig both = make_config("anon", "pw");
  CHECK(!same_encoding(user_only, both));
  CHECK(!same_encoding(pass_only, both));
  CHECK(!same_encoding(user_only, pass_only));

  struct case_t {
    InjectorConfig cfg;
    const char *user;  // nullptr: the field must stay absent
    const char *pass;
  };
  for (const auto &c : std::vector<case_t>{{user_only, "anon", nullptr},
                                           {pass_only, nullptr, "pw"},
                                           {both, "anon", "pw"}}) {
    const auto back = decode<InjectorConfig>(encode(c.cfg));
    CHECK(back.has_value());
    if (!back) {
      continue;
    }
    CHECK(same_encoding(c.cfg, *back));
    const auto got_user = (*back)["username"_f];
    const auto got_pass = (*back)["password"_f];
    CHECK_EQ(static_cast<bool>(got_user), c.user != nullptr);
    CHECK_EQ(static_cast<bool>(got_pass), c.pass != nullptr);
    if (c.user) {
      CHECK_EQ(*got_user, std::string(c.user));
    }
    if (c.pass) {
      CHECK_EQ(*got_pass, std::string(c.pass));
    }
  }

  // "none" is ABSENT, not empty: an explicitly-set empty string is a present
  // field, so a frontend that means "no credentials" has to omit it (S4/S5).
  InjectorConfig blank_user = make_config();
  blank_user["username"_f] = std::string();
  CHECK(encode(blank_user) != encode(make_config()));
  const auto blank_back = decode<InjectorConfig>(encode(blank_user));
  CHECK(blank_back.has_value());
  if (blank_back) {
    CHECK((*blank_back)["username"_f].has_value());
    CHECK_EQ((*blank_back)["username"_f]->size(),
             static_cast<std::size_t>(0));
  }

  // A credentials-only message is nothing but that one field, tagged 4 or 5.
  std::vector<std::byte> want;
  append(want, delimited_field(kUsernameTag, "anon"));
  CHECK(encode(InjectorConfig{{}, {}, {}, std::string("anon"), {}}) == want);

  want.clear();
  append(want, delimited_field(kPasswordTag, "pw"));
  CHECK(encode(InjectorConfig{{}, {}, {}, {}, std::string("pw")}) == want);
}

// No caps at this layer: 255-byte credentials round-trip, because the schema
// just carries the bytes and the frontends enforce their own limits.
void injector_config_long_credentials() {
  const std::string user(255, 'u');
  const std::string pass(255, 'p');
  const InjectorConfig cfg = make_config(user, pass);

  const auto back = decode<InjectorConfig>(encode(cfg));
  CHECK(back.has_value());
  if (back) {
    CHECK_EQ((*back)["username"_f]->size(), static_cast<std::size_t>(255));
    CHECK_EQ((*back)["password"_f]->size(), static_cast<std::size_t>(255));
    CHECK_EQ(*(*back)["username"_f], user);
    CHECK_EQ(*(*back)["password"_f], pass);
    CHECK(same_encoding(cfg, *back));
  }

  // 255 does not fit one octet, so LEN becomes the two-octet varint 0xFF 0x01
  // and each field is 258 bytes: tag + varint + payload.
  std::vector<std::byte> want;
  const auto push_long = [&](std::uint8_t tag, char fill) {
    want.push_back(static_cast<std::byte>(tag));
    want.push_back(std::byte{0xFF});
    want.push_back(std::byte{0x01});
    for (int i = 0; i < 255; ++i) {
      want.push_back(static_cast<std::byte>(static_cast<unsigned char>(fill)));
    }
  };
  push_long(kUsernameTag, 'u');
  push_long(kPasswordTag, 'p');

  const auto bare = encode(InjectorConfig{{}, {}, {}, user, pass});
  CHECK(bare == want);
  CHECK_EQ(bare.size(), static_cast<std::size_t>(2 * 258));
}

// The other half of the contract: credentials go IN, they never come BACK.  A
// report message has no field to carry them in, by count and by content.
void report_messages_carry_no_credential_fields() {
  CHECK_EQ(static_cast<unsigned>(InjectorConfig::size), 5u);  // +user +pass
  CHECK_EQ(static_cast<unsigned>(InjectorMessage::size), 2u);
  CHECK_EQ(static_cast<unsigned>(InjecteeMessage::size), 5u);  // opcode..token
  CHECK_EQ(static_cast<unsigned>(InjecteeConnect::size),
           4u);  // handle, addr, proxy, syscall
  CHECK_EQ(static_cast<unsigned>(IpAddr::size), 4u);

  // The injector direction does emit them -- this is the one place they ride.
  const InjectorMessage config =
      create_message<InjectorMessage, "config">(make_config("alice",
                                                            "s3cr3t!"));
  CHECK(contains(encode(config), "s3cr3t!"));

  // The fullest report an injectee can send: a connect payload naming the
  // same proxy, both pids and a token.  None of it holds a credential.
  InjecteeMessage report = create_message<InjecteeMessage, "connect">(
      InjecteeConnect{0x1234u, IpAddr{0x7F000001u, {}, {}, 80u},
                      IpAddr{{}, {}, std::string("proxy.example.com"), 1080u},
                      std::string("connect")});
  report["pid"_f] = 42u;
  report["subpid"_f] = 43u;
  report["token"_f] = std::vector<unsigned char>(8, 0xABu);

  const auto report_bytes = encode(report);
  CHECK(!contains(report_bytes, "s3cr3t!"));
  CHECK(!contains(report_bytes, "alice"));

  const auto pid_report = create_message<InjecteeMessage, "pid">(42u);
  CHECK(!contains(encode(pid_report), "alice"));
  CHECK(!contains(encode(pid_report), "s3cr3t!"));
}

} // namespace

int main() {
  RUN(ipaddr_fields);
  RUN(injectee_message_roundtrip);
  RUN(injector_message_roundtrip);
  RUN(create_and_compare);
  RUN(asio_symmetry);
  RUN(truncated_buffer);
  RUN(injectee_token_field);
  RUN(mapping_payload_layout);
  RUN(injector_config_credentials_round_trip);
  RUN(injector_config_without_credentials_is_wire_identical);
  RUN(injector_config_credential_fields_are_independent);
  RUN(injector_config_long_credentials);
  RUN(report_messages_carry_no_credential_fields);
  return test_failures;
}
