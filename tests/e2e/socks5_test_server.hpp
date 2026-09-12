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

#ifndef ENCAPSULE_E2E_SOCKS5_TEST_SERVER
#define ENCAPSULE_E2E_SOCKS5_TEST_SERVER

// A header-only socks5 CONNECT relay for the end-to-end smoke test.
//
// It speaks exactly the client half of src/injectee/socks5.hpp: greeting
// {5, nmethods, ...} -> {5, 0}; request {5, 1, 0, atyp, addr, port} -> the
// 10-byte IPv4 success reply that socks5_request_send() reads (4 bytes, then
// 6 more because ATYP is IPv4); afterwards every byte is echoed back.
//
// Each CONNECT is recorded so a test can assert what the injectee asked the
// proxy for.  An optional on_connect hook decides the reply code, which lets a
// test prove the failure path too.
//
// RFC 1928 section 7 is served too -- but ONLY once enable_udp_relay(true)
// has been called, which no test in this suite does yet.  With the flag down a
// CMD=3 ends the session exactly as it always did, before its address is read
// and before anything is recorded, so the TCP walk stays byte-for-byte the one
// P5 pinned.  With it up, a CMD=3 ASSOCIATE gets a UDP socket of the
// relay's own, bound to loopback, and an answer carrying that socket's REAL
// BND.ADDR/BND.PORT.  Both legs are then pumped by the same one worker thread
// through a select() over {control TCP, relay UDP}, so the header keeps its
// "no new thread, every I/O bounded" discipline.  Each datagram's section 7
// header is decoded with the injectee's own socks5_parse_udp_header(),
// recorded, and echoed to the peer it came from with the SRC and DST ends
// swapped.  FRAG != 0 is dropped and counted; so is anything malformed.
// Neither ever closes the session.
//
// Authentication is OFF by default, which keeps the whole no-auth walk above
// byte-for-byte what it was.  require_auth(true) turns on RFC 1929: a client
// that offered method 2 gets {5, 2}, then its {1, ULEN, USER, PLEN, PASS}
// subnegotiation is parsed and judged by the auth hook, and it gets {1, 0} or
// {1, 0xFF} -- a refusal closes the session right there, and a client that
// offered nothing to auth with gets {5, 0xFF}.  Every greeting is recorded,
// accepted or not, in offered order.
//
// CREDENTIALS NEVER GET LOGGED.  Nothing in here prints a username or a
// password; traces name lengths and verdicts only.
//
// THREADING: one worker thread, one session at a time, all I/O polled with a
// bounded idle timeout so ~socks5_test_server() never hangs.  That is plenty
// for a decoy that opens one connection, exchanges a sentinel and closes.
//
// NOTE: <socks5.hpp> is guarded (since 410a54e) but still DEFINES socket
// functions at namespace scope without inline, so this header belongs to
// exactly one translation unit (e2e_test.cpp).  Its pure byte builders are
// inline, so this relay and the tests can share one spelling of the wire.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <asio.hpp>

// schema.hpp, pulled in by socks5.hpp, spells asio::ip as plain ip::
namespace ip = asio::ip;

#include <socks5.hpp>

namespace e2e {

// One CONNECT request as observed on the wire.
struct socks5_request_record {
  char atyp = 0;          // SOCKS_IPV4 / SOCKS_DOMAINNAME / SOCKS_IPV6
  std::string addr;       // dotted quad, domain text, or ipv6 text
  std::uint16_t port = 0; // host byte order
};

// One session's authentication attempt, newest last.  Public so tests can
// assert on it; never print username or password from in here -- in the
// general case they are live credentials, and this relay is reused by tests
// that run against the real product.
struct socks5_auth_record {
  std::vector<std::uint8_t> offered;  // METHODS from the greeting, in order
  bool chose_auth = false;            // the relay answered {5, 2}
  bool parsed = false;                // a complete 1929 request was read
  bool ok = false;                    // the hook's verdict (refuse if no hook)
  std::string username;
  std::string password;
};

// One datagram the UDP leg relayed, as its section 7 header described it.
// src_* is the peer recvfrom() saw: a section 7 REQUEST header carries only a
// DST, so the source is what the socket observed, and it is also where the
// echo went back to.  dst_* is the header's own address, which in the reply
// becomes the SRC the client is told the data came from.  payload is
// everything after the header, byte for byte (empty for a header-only packet).
struct socks5_datagram_record {
  std::uint8_t atyp = 0;         // ATYP from the header
  std::string src_addr;          // dotted quad of the recvfrom peer
  std::uint16_t src_port = 0;    // host order
  std::string dst_addr;          // as the header spelled it
  std::uint16_t dst_port = 0;    // host order
  std::size_t header_size = 0;   // where DATA began
  std::vector<char> payload;
};

inline std::string method_list_text(const std::vector<std::uint8_t> &methods) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  for (const std::uint8_t m : methods) {
    if (!out.empty()) {
      out += ' ';
    }
    out += digits[m >> 4];
    out += digits[m & 0xF];
  }
  return out;
}

inline std::string atyp_name(char atyp) {
  switch (atyp) {
  case SOCKS_IPV4:
    return "IPV4";
  case SOCKS_DOMAINNAME:
    return "DOMAINNAME";
  case SOCKS_IPV6:
    return "IPV6";
  default:
    return "UNKNOWN";
  }
}

class socks5_test_server {
public:
  using request = socks5_request_record;
  using hook_type = std::function<char(const request &)>;
  // Judges one RFC 1929 attempt: true -> {1, 00}, false -> {1, FF}.
  using auth_hook_type =
      std::function<bool(const std::string &, const std::string &)>;

  // port 0 -> let the OS pick, so parallel runs never collide.
  explicit socks5_test_server(std::uint16_t port = 0,
                              std::string listen_addr = "127.0.0.1")
      : listen_addr_(std::move(listen_addr)), io_(), acceptor_(io_) {
    asio::error_code ec;
    ip::address addr = ip::make_address(listen_addr_, ec);
    if (ec) {
      throw std::runtime_error("e2e: bad listen address " + listen_addr_);
    }
    const ip::tcp::endpoint ep(addr, port);
    acceptor_.open(ep.protocol(), ec);
    if (!ec) {
      acceptor_.bind(ep, ec);
    }
    if (!ec) {
      acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    }
    if (ec) {
      throw std::runtime_error("e2e: cannot listen: " + ec.message());
    }
    port_ = acceptor_.local_endpoint(ec).port();
    acceptor_.non_blocking(true, ec); // so the accept loop can poll stop_
    worker_ = std::thread([this] { accept_loop(); });
  }

  socks5_test_server(const socks5_test_server &) = delete;
  socks5_test_server &operator=(const socks5_test_server &) = delete;

  ~socks5_test_server() {
    stop_.store(true);
    if (worker_.joinable()) {
      worker_.join();
    }
  }

  std::uint16_t port() const { return port_; }
  const std::string &address() const { return listen_addr_; }

  // Copies of every CONNECT seen so far, newest last.
  std::vector<request> requests() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return records_;
  }

  std::size_t request_count() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return records_.size();
  }

  std::size_t auth_count() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return auth_records_.size();
  }

  // ------------------------------------------------ the UDP leg's switch
  //
  // Turn RFC 1928 section 7 on or off.  OFF is the default and the point: the
  // leg exists for the future P7-S7 pump test, and until a test asks for it the
  // relay must answer a CMD=3 exactly as it did before this code landed -- end
  // the session, no reply, no record.  Set it before the client connects.
  void enable_udp_relay(bool enabled) {
    std::lock_guard<std::mutex> guard(mutex_);
    udp_relay_enabled_ = enabled;
  }

  bool udp_relay_enabled() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return udp_relay_enabled_;
  }

  // ------------------------------------------------ the UDP leg's evidence
  //
  // Copies of every datagram this relay echoed, newest last.
  std::vector<socks5_datagram_record> datagrams() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return datagram_records_;
  }

  std::size_t datagram_count() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return datagram_records_.size();
  }

  // Echoed plus the three drops: these four counters together
  // are every datagram a leg was handed, so no packet can
  // vanish silently on the floor.
  std::size_t echoed_datagrams() const { return datagrams_echoed_.load(); }
  std::size_t fragments_dropped() const { return fragments_dropped_.load(); }
  std::size_t malformed_dropped() const { return malformed_dropped_.load(); }

  // The BND an ASSOCIATE was answered with, zero until one is granted.  The
  // address is the listen address by construction: the UDP socket binds to
  // loopback and to nothing else.
  std::uint16_t udp_port() const { return udp_port_.load(); }
  const std::string &udp_address() const { return listen_addr_; }

  // The same polling contract as the two waits above, for datagrams.
  bool wait_for_datagram_count(
      std::size_t n, std::chrono::milliseconds timeout,
      std::chrono::milliseconds step = std::chrono::milliseconds(50)) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (datagram_count() < n) {
      if (std::chrono::steady_clock::now() >= deadline) {
        return false;
      }
      std::this_thread::sleep_for(step);
    }
    return true;
  }

  // A sendto() that failed after a perfectly good header: counted apart, so a
  // test never mistakes it for a header this relay refused to read.
  std::size_t echo_failures() const { return echo_failures_.load(); }

  // Decide the reply for each CONNECT; return SOCKS_SUCCESS to let the
  // echo-loop start, anything else to refuse the request.  Set it before
  // spawning the client; the hook must not outlive the server.
  void set_on_connect(hook_type hook) {
    std::lock_guard<std::mutex> guard(mutex_);
    on_connect_ = std::move(hook);
  }

  // Demand (or stop demanding) RFC 1929 credentials.  Default false, which
  // leaves the no-auth walk byte-for-byte alone.  Set it before the client.
  void require_auth(bool required) {
    std::lock_guard<std::mutex> guard(mutex_);
    auth_required_ = required;
  }

  bool auth_required() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return auth_required_;
  }

  // Set the judge.  Deliberately NO accept-all default: a relay that demands
  // auth with no hook installed refuses every login.
  void set_auth_hook(auth_hook_type hook) {
    std::lock_guard<std::mutex> guard(mutex_);
    auth_hook_ = std::move(hook);
  }

  // Copies of every greeting seen so far (accepted or not), newest last.
  std::vector<socks5_auth_record> auth_records() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return auth_records_;
  }

  std::size_t echoed_round_trips() const { return echoed_round_trips_.load(); }
  std::size_t echoed_bytes() const { return echoed_bytes_.load(); }

  // Polls the record list (50ms per the harness contract) until n CONNECTs
  // have landed or timeout expires.
  bool wait_for_request_count(
      std::size_t n, std::chrono::milliseconds timeout,
      std::chrono::milliseconds step = std::chrono::milliseconds(50)) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (request_count() < n) {
      if (std::chrono::steady_clock::now() >= deadline) {
        return false;
      }
      std::this_thread::sleep_for(step);
    }
    return true;
  }

  // Same polling contract, for greetings and authentication attempts.
  bool wait_for_auth_count(
      std::size_t n, std::chrono::milliseconds timeout,
      std::chrono::milliseconds step = std::chrono::milliseconds(50)) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (auth_count() < n) {
      if (std::chrono::steady_clock::now() >= deadline) {
        return false;
      }
      std::this_thread::sleep_for(step);
    }
    return true;
  }

private:
  static constexpr int kHandshakeIdleMs = 5000;
  static constexpr int kEchoIdleMs = 500;
  static constexpr int kPollMs = 10;

  void accept_loop() {
    while (!stop_.load()) {
      asio::error_code ec;
      ip::tcp::socket sock(io_);
      acceptor_.accept(sock, ec);
      if (!ec) {
        handle_session(sock);
        continue;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(kPollMs * 2));
    }
  }

  void handle_session(ip::tcp::socket &sock) {
    asio::error_code ec;
    sock.non_blocking(false, ec); // accepted sockets inherit non-blocking

    char greeting[2] = {};
    if (!read_exact(sock, greeting, 2, kHandshakeIdleMs)) {
      return;
    }
    if (greeting[0] != SOCKS_VERSION) {
      return; // not a socks5 client at all
    }
    const int nmethods = static_cast<unsigned char>(greeting[1]);
    if (nmethods < 0 || nmethods > 255) {
      return;
    }
    std::vector<char> methods(static_cast<std::size_t>(nmethods), '\0');
    if (!read_exact(sock, methods.data(), methods.size(), kHandshakeIdleMs)) {
      return;
    }
    // What the client offered, recorded for every session -- whatever the
    // relay decides next.  This is the one question P5 asks the wire.
    socks5_auth_record auth_rec;
    auth_rec.offered.assign(methods.begin(), methods.end());
    const bool offered_auth =
        std::find(methods.begin(), methods.end(), SOCKS_USERNAME_PASSWORD) !=
        methods.end();

    bool required = false;
    auth_hook_type auth_hook;
    {
      std::lock_guard<std::mutex> guard(mutex_);
      required = auth_required_;
      auth_hook = auth_hook_;
    }

    if (!required) {
      // Auth not demanded: byte-for-byte the reply this relay has always
      // given, even against a client that offered method 2.  A proxy with
      // authentication disabled really does answer {5, 00}.
      const char chosen[2] = {SOCKS_VERSION, SOCKS_NO_AUTHENTICATION};
      if (!write_all(sock, chosen, sizeof(chosen))) {
        return;
      }
      record_auth(auth_rec);
      if (offered_auth) {
        std::printf("  [relay] offered [%s], auth not required -> 05 00\n",
                    method_list_text(auth_rec.offered).c_str());
      }
    } else if (!offered_auth) {
      // Demanded, and the client had nothing to offer.  RFC 1928: {5, FF},
      // "no acceptable methods" -- and the session ends before any login.
      const char refused[2] = {SOCKS_VERSION, static_cast<char>(0xFF)};
      write_all(sock, refused, sizeof(refused));
      record_auth(auth_rec);
      std::printf("  [relay] auth demanded, offered [%s] -> 05 ff\n",
                  method_list_text(auth_rec.offered).c_str());
      return;
    } else {
      const char chosen[2] = {SOCKS_VERSION, SOCKS_USERNAME_PASSWORD};
      auth_rec.chose_auth = true;
      if (!write_all(sock, chosen, sizeof(chosen))) {
        record_auth(auth_rec);
        return;
      }
      // A malformed 1929 request is a refusal, not a crash: answer {1, FF}
      // with whatever was parsed and close the session.
      if (!read_auth(sock, auth_rec)) {
        const char refused[2] = {static_cast<char>(SOCKS_AUTH_VERSION),
                                 static_cast<char>(SOCKS_AUTH_FAILURE)};
        write_all(sock, refused, sizeof(refused));
        record_auth(auth_rec);
        std::printf("  [relay] malformed 1929 request -> 01 ff\n");
        return;
      }
      auth_rec.ok =
          auth_hook ? auth_hook(auth_rec.username, auth_rec.password) : false;
      const char verdict[2] = {
          static_cast<char>(SOCKS_AUTH_VERSION),
          auth_rec.ok ? static_cast<char>(SOCKS_SUCCESS)
                      : static_cast<char>(SOCKS_AUTH_FAILURE)};
      record_auth(auth_rec);
      std::printf("  [relay] %s [%s] user=%zu pass=%zu -> 01 %02x\n",
                  auth_rec.ok ? "accepted" : "refused",
                  method_list_text(auth_rec.offered).c_str(),
                  auth_rec.username.size(), auth_rec.password.size(),
                  static_cast<unsigned char>(verdict[1]));
      if (!write_all(sock, verdict, sizeof(verdict))) {
        return;
      }
      if (!auth_rec.ok) {
        return;  // a refused login closes the session: no CONNECT follows
      }
    }

    char head[4] = {};
    if (!read_exact(sock, head, 4, kHandshakeIdleMs)) {
      return;
    }
    // CONNECT and UDP ASSOCIATE only.  BIND stays out of scope, and a request
    // for it ends the session exactly as it always did.  The two commands
    // share every octet below: section 4's request and section 7's associate
    // are the same {VER, CMD, RSV, ATYP, ADDR, PORT} shape, and only the CMD
    // octet differs -- which is why this relay can parse both with one walk.
    bool udp_ok = false;
    {
      std::lock_guard<std::mutex> guard(mutex_);
      udp_ok = udp_relay_enabled_;
    }
    const bool associate =
        udp_ok && head[1] == static_cast<char>(SOCKS_UDP_ASSOCIATE);
    if (head[0] != SOCKS_VERSION ||
        (head[1] != SOCKS_CONNECT && !associate)) {
      return;
    }

    request rec;
    rec.atyp = head[3];
    bool parsed = false;
    if (head[3] == SOCKS_IPV4) {
      char raw[4] = {};
      parsed = read_exact(sock, raw, 4, kHandshakeIdleMs);
      rec.addr = ipv4_text(raw);
    } else if (head[3] == SOCKS_DOMAINNAME) {
      char len = 0;
      parsed = read_exact(sock, &len, 1, kHandshakeIdleMs);
      if (parsed) {
        const std::size_t n = static_cast<unsigned char>(len);
        rec.addr.resize(n);
        parsed = n == 0 || read_exact(sock, &rec.addr[0], n, kHandshakeIdleMs);
      }
    } else if (head[3] == SOCKS_IPV6) {
      char raw[16] = {};
      parsed = read_exact(sock, raw, 16, kHandshakeIdleMs);
      rec.addr = ipv6_text(raw);
    }
    if (!parsed) {
      return;
    }

    char port_raw[2] = {};
    if (!read_exact(sock, port_raw, 2, kHandshakeIdleMs)) {
      return;
    }
    rec.port = static_cast<std::uint16_t>(
        (static_cast<std::uint8_t>(port_raw[0]) << 8) |
        static_cast<std::uint8_t>(port_raw[1]));

    record(rec);

    hook_type hook;
    {
      std::lock_guard<std::mutex> guard(mutex_);
      hook = on_connect_;
    }
    const char verdict = hook ? hook(rec) : SOCKS_SUCCESS;
    if (associate) {
      // Recorded like any other request, because an ASSOCIATE is one -- but
      // its answer carries a real BND and what follows it is the two-leg pump
      // rather than the TCP echo loop.
      udp_associate(sock, verdict);
      return;
    }
    if (!send_reply(sock, verdict)) {
      return;
    }
    if (verdict != SOCKS_SUCCESS) {
      return;
    }
    echo_loop(sock);
  }

  bool send_reply(ip::tcp::socket &sock, char verdict) {
    // VER REP RSV ATYP + BND.ADDR(4) + BND.PORT(2): the shape the injectee's
    // socks5_request_send() expects after it reads the first 4 bytes.
    const char reply[10] = {SOCKS_VERSION, verdict, 0,   SOCKS_IPV4, 0,
                            0,             0,       0,   0,          0};
    return write_all(sock, reply, sizeof(reply));
  }

  void echo_loop(ip::tcp::socket &sock) {
    char buf[256];
    auto quiet = std::chrono::steady_clock::now();
    while (!stop_.load()) {
      asio::error_code ec;
      const std::size_t avail = sock.available(ec);
      if (ec) {
        return;
      }
      if (avail == 0) {
        if (std::chrono::steady_clock::now() - quiet >=
            std::chrono::milliseconds(kEchoIdleMs)) {
          return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kPollMs));
        continue;
      }
      quiet = std::chrono::steady_clock::now();
      const std::size_t want = avail < sizeof(buf) ? avail : sizeof(buf);
      const std::size_t got = sock.read_some(asio::buffer(buf, want), ec);
      if (ec || got == 0) {
        return;
      }
      if (!write_all(sock, buf, got)) {
        return;
      }
      echoed_bytes_.fetch_add(got);
      echoed_round_trips_.fetch_add(1);
    }
  }

  // ------------------------------------------------------- UDP ASSOCIATE --
  //
  // How long an association may sit with nothing on either leg before the
  // session ends.  Every I/O in here is bounded, and this one has to be too:
  // ~socks5_test_server() joins the worker, and a client that walked away
  // must not be able to hold it open forever.
  static constexpr int kAssociateIdleMs = 5000;
  static constexpr int kUdpDatagramMax = 4096;

  // The section 5 reply with the relay's OWN bound endpoint in BND:
  // {5, REP, 0, 1, a0, a1, a2, a3, p_hi, p_lo}.  send_reply() keeps writing the
  // all-zero BND it has always written for CONNECT -- that byte string is
  // pinned elsewhere and must not move; only an ASSOCIATE answer gets a
  // real one.  socks5_write_port() puts the port on the wire most
  // significant octet first: the order the injectee reader decodes, and
  // the octet order P4 got backwards once already.
  bool send_bound_reply(ip::tcp::socket &sock, char verdict,
                        const std::string &addr, std::uint16_t port) {
    asio::error_code ec;
    const ip::address bound = ip::make_address(addr, ec);
    if (ec || !bound.is_v4()) {
      return false; // this relay answers a v4 BND and nothing else
    }
    const auto octets = bound.to_v4().to_bytes(); // network order already
    char reply[10] = {SOCKS_VERSION, verdict, 0,   SOCKS_IPV4, 0,
                      0,             0,       0,   0,          0};
    reply[4] = static_cast<char>(octets[0]);
    reply[5] = static_cast<char>(octets[1]);
    reply[6] = static_cast<char>(octets[2]);
    reply[7] = static_cast<char>(octets[3]);
    socks5_write_port(reply + 8, port);
    return write_all(sock, reply, sizeof(reply));
  }

  // RFC 1928 section 7 from the server side, on the thread that already owns
  // the control connection.  No new thread and no reactor: select() over the
  // two native handles with a kPollMs tick, so stop_ is still noticed within a
  // tick, the idle bound above still applies, and the header keeps its one
  // worker thread.  Both legs are served in the same loop: bytes the client
  // writes on the control socket still come back (it is the same session that
  // a CONNECT gets), and closing it ends the association with it.
  void udp_associate(ip::tcp::socket &control, char verdict) {
    asio::error_code ec;
    // Loopback only, port zero so the OS picks the BND.PORT this reply will
    // carry.  open()/bind() rather than the endpoint constructor because the
    // datagram socket has no (executor, endpoint, error_code) overload: this
    // header reports failures by answering REP=4, not by throwing mid-session.
    const ip::address bind_to = ip::make_address(listen_addr_, ec);
    if (ec || !bind_to.is_v4()) {
      send_reply(control, SOCKS_GENERAL_FAILURE);
      return;
    }
    ip::udp::socket relay(io_);
    relay.open(ip::udp::v4(), ec);
    if (!ec) {
      relay.bind(ip::udp::endpoint(bind_to, 0u), ec);
    }
    if (ec) {
      std::printf("  [relay] ASSOCIATE cannot bind UDP: %s\n",
                  ec.message().c_str());
      send_reply(control, SOCKS_GENERAL_FAILURE);
      return;
    }
    const ip::udp::endpoint bound = relay.local_endpoint(ec);
    if (ec || !bound.address().is_v4()) {
      send_reply(control, SOCKS_GENERAL_FAILURE);
      return;
    }
    const std::uint16_t port = static_cast<std::uint16_t>(bound.port());
    udp_port_.store(port);
    std::printf("  [relay] ASSOCIATE granted, BND %s:%u\n",
                listen_addr_.c_str(), static_cast<unsigned>(port));
    if (!send_bound_reply(control, verdict, listen_addr_, port)) {
      return;
    }
    if (verdict != SOCKS_SUCCESS) {
      return; // refused: the answer went out, there is nothing to pump
    }

    const SOCKET ctl = control.native_handle();
    const SOCKET ud = relay.native_handle();
    char buf[kUdpDatagramMax];
    auto quiet = std::chrono::steady_clock::now();
    while (!stop_.load()) {
      if (std::chrono::steady_clock::now() - quiet >=
          std::chrono::milliseconds(kAssociateIdleMs)) {
        std::printf("  [relay] association idled out\n");
        return;
      }
      fd_set readfds;
      FD_ZERO(&readfds);
      FD_SET(ctl, &readfds);
      FD_SET(ud, &readfds);
      timeval tv = {};
      tv.tv_sec = 0;
      tv.tv_usec = kPollMs * 1000;
      // Windows ignores the first argument; the two sets say what we mean.
      const int ready = ::select(0, &readfds, nullptr, nullptr, &tv);
      if (ready == SOCKET_ERROR) {
        std::printf("  [relay] select failed (%d)\n", WSAGetLastError());
        return;
      }
      if (ready == 0) {
        continue; // a tick with nothing readable: the idle bound decides
      }
      quiet = std::chrono::steady_clock::now();
      if (FD_ISSET(ctl, &readfds)) {
        const int n = ::recv(ctl, buf, sizeof(buf), 0);
        if (n <= 0) {
          return; // the client hung up, so the association ends with it
        }
        if (::send(ctl, buf, n, 0) <= 0) {
          return;
        }
        echoed_bytes_.fetch_add(static_cast<std::size_t>(n));
        echoed_round_trips_.fetch_add(1);
      }
      if (FD_ISSET(ud, &readfds)) {
        sockaddr_in from = {};
        int from_len = static_cast<int>(sizeof(from));
        const int n = ::recvfrom(ud, buf, sizeof(buf), 0,
                                 reinterpret_cast<sockaddr *>(&from),
                                 &from_len);
        if (n > 0) {
          relay_datagram(ud, buf, static_cast<std::size_t>(n), from);
        }
      }
    }
  }

  // A section 7 address as text, the same way the CONNECT records spell one.
  static std::string datagram_addr_text(const socks5_udp_datagram &hdr) {
    const char *raw = reinterpret_cast<const char *>(hdr.addr.data());
    if (hdr.atyp == SOCKS_IPV4) {
      return ipv4_text(raw);
    }
    if (hdr.atyp == SOCKS_IPV6) {
      return ipv6_text(raw);
    }
    // A domain: the parser proved LEN >= 1, and header_size = 7 + LEN.
    const std::size_t name_len = hdr.header_size - 7;
    return std::string(hdr.addr.begin(), hdr.addr.begin() + name_len);
  }

  // One datagram off the relay's UDP socket.  Nothing in here may close the
  // session: a proxy does not die of a bad packet and neither does this relay,
  // so every unusable input is a drop plus a counter.
  void relay_datagram(SOCKET ud, const char *buf, std::size_t len,
                      const sockaddr_in &from) {
    // RSV, RSV, FRAG: the three octets that must exist before anything else
    // can be said about the packet.  Shorter than that is malformed.
    if (len < 3) {
      malformed_dropped_.fetch_add(1);
      return;
    }
    const auto frag = static_cast<std::uint8_t>(buf[2]);
    if (frag != SOCKS_FRAG_NOT) {
      // A continuation piece carries DATA where the address would be, so
      // decoding it would invent an origin out of payload octets.  Counted.
      fragments_dropped_.fetch_add(1);
      std::printf("  [relay] dropped FRAG=%u datagram (%zu octets)\n",
                  static_cast<unsigned>(frag), len);
      return;
    }
    const auto hdr = socks5_parse_udp_header(buf, len);
    if (!hdr) {
      malformed_dropped_.fetch_add(1);
      std::printf("  [relay] dropped malformed datagram (%zu octets)\n", len);
      return;
    }

    // The reply header carries the SAME address the request named, because in
    // a section 7 REPLY that field is SRC: the client is told the data came
    // from what it asked for.  Where it goes is the peer recvfrom() reported,
    // which is the request's SRC -- so the two ends of the exchange really do
    // swap, and the client's own stack accepts the packet.
    char out[SOCKS_UDP_HEADER_MAX + kUdpDatagramMax];
    std::size_t head = 0;
    if (hdr->atyp == SOCKS_DOMAINNAME) {
      const std::size_t name_len = hdr->header_size - 7; // parser-checked
      const std::string name(hdr->addr.begin(),
                             hdr->addr.begin() + name_len);
      head = socks5_build_udp_header(hdr->atyp, name.c_str(),
                                     hdr->port_host_order, SOCKS_FRAG_NOT, out);
    } else {
      head = socks5_build_udp_header(hdr->atyp, hdr->addr.data(),
                                     hdr->port_host_order, SOCKS_FRAG_NOT, out);
    }
    const std::size_t payload_len = len - hdr->header_size;
    if (head == 0 || head + payload_len > sizeof(out)) {
      malformed_dropped_.fetch_add(1);
      return;
    }
    std::memcpy(out + head, buf + hdr->header_size, payload_len);

    socks5_datagram_record rec;
    rec.atyp = hdr->atyp;
    rec.src_addr = ipv4_text(reinterpret_cast<const char *>(&from.sin_addr));
    rec.src_port = ntohs(from.sin_port);
    rec.dst_addr = datagram_addr_text(*hdr);
    rec.dst_port = hdr->port_host_order;
    rec.header_size = hdr->header_size;
    rec.payload.assign(buf + hdr->header_size, buf + len);

    const int sent = ::sendto(ud, out, static_cast<int>(head + payload_len), 0,
                              reinterpret_cast<const sockaddr *>(&from),
                              static_cast<int>(sizeof(from)));
    if (sent <= 0) {
      echo_failures_.fetch_add(1);
      std::printf("  [relay] echo sendto failed (%d)\n", WSAGetLastError());
      return;
    }
    record_datagram(rec);
    datagrams_echoed_.fetch_add(1);
    std::printf("  [relay] %s:%u -> %s(%s):%u, %zu payload octet(s) echoed\n",
                rec.src_addr.c_str(), static_cast<unsigned>(rec.src_port),
                e2e::atyp_name(hdr->atyp).c_str(), rec.dst_addr.c_str(),
                static_cast<unsigned>(rec.dst_port), payload_len);
  }

  bool read_exact(ip::tcp::socket &sock, char *dst, std::size_t n,
                  int idle_ms) {
    std::size_t got = 0;
    auto quiet = std::chrono::steady_clock::now();
    while (got < n) {
      if (stop_.load()) {
        return false;
      }
      asio::error_code ec;
      const std::size_t avail = sock.available(ec);
      if (ec) {
        return false;
      }
      if (avail == 0) {
        if (std::chrono::steady_clock::now() - quiet >=
            std::chrono::milliseconds(idle_ms)) {
          return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kPollMs));
        continue;
      }
      quiet = std::chrono::steady_clock::now();
      const std::size_t k =
          sock.read_some(asio::buffer(dst + got, n - got), ec);
      if (ec) {
        return false;
      }
      got += k;
    }
    return true;
  }

  bool write_all(ip::tcp::socket &sock, const char *src, std::size_t n) {
    asio::error_code ec;
    const std::size_t written = asio::write(sock, asio::buffer(src, n), ec);
    return !ec && written == n;
  }

  // Reads one client subnegotiation {VER=1, ULEN, USER, PLEN, PASS}.  False on
  // a short read or a wrong VER; whatever was parsed stays in the record,
  // because "what did it send" is exactly what a test wants to know.
  bool read_auth(ip::tcp::socket &sock, socks5_auth_record &rec) {
    char head[2] = {};
    if (!read_exact(sock, head, 2, kHandshakeIdleMs)) {
      return false;
    }
    if (static_cast<std::uint8_t>(head[0]) != SOCKS_AUTH_VERSION) {
      return false;
    }
    const std::size_t ulen = static_cast<std::uint8_t>(head[1]);
    rec.username.resize(ulen);
    if (ulen > 0 &&
        !read_exact(sock, &rec.username[0], ulen, kHandshakeIdleMs)) {
      return false;
    }
    char plen_byte = 0;
    if (!read_exact(sock, &plen_byte, 1, kHandshakeIdleMs)) {
      return false;
    }
    const std::size_t plen = static_cast<std::uint8_t>(plen_byte);
    rec.password.resize(plen);
    if (plen > 0 &&
        !read_exact(sock, &rec.password[0], plen, kHandshakeIdleMs)) {
      return false;
    }
    rec.parsed = true;
    return true;
  }

  void record(const request &rec) {
    std::lock_guard<std::mutex> guard(mutex_);
    records_.push_back(rec);
  }

  void record_auth(const socks5_auth_record &rec) {
    std::lock_guard<std::mutex> guard(mutex_);
    auth_records_.push_back(rec);
  }

  void record_datagram(const socks5_datagram_record &rec) {
    std::lock_guard<std::mutex> guard(mutex_);
    datagram_records_.push_back(rec);
  }

  static std::string ipv4_text(const char *raw) {
    return std::to_string(static_cast<unsigned char>(raw[0])) + "." +
           std::to_string(static_cast<unsigned char>(raw[1])) + "." +
           std::to_string(static_cast<unsigned char>(raw[2])) + "." +
           std::to_string(static_cast<unsigned char>(raw[3]));
  }

  static std::string ipv6_text(const char *raw) {
    static const char *digits = "0123456789abcdef";
    std::string out;
    for (int i = 0; i < 16; i += 2) {
      if (i) {
        out += ':';
      }
      const unsigned hi = static_cast<unsigned char>(raw[i]);
      const unsigned lo = static_cast<unsigned char>(raw[i + 1]);
      out += digits[hi >> 4];
      out += digits[hi & 0xF];
      out += digits[lo >> 4];
      out += digits[lo & 0xF];
    }
    return out;
  }

  std::string listen_addr_;
  std::uint16_t port_ = 0;
  asio::io_context io_;
  ip::tcp::acceptor acceptor_;
  std::thread worker_;
  std::atomic<bool> stop_{false};

  mutable std::mutex mutex_;
  std::vector<request> records_;
  hook_type on_connect_;
  std::vector<socks5_auth_record> auth_records_;
  bool auth_required_ = false;  // off => the pre-P5 no-auth relay, unchanged
  auth_hook_type auth_hook_;    // empty + required => refuse everything
  std::atomic<std::size_t> echoed_round_trips_{0};
  std::atomic<std::size_t> echoed_bytes_{0};
  // --- the UDP leg, RFC 1928 section 7 ------------------------------------
  //
  // udp_relay_enabled_ is the section 7 switch, off until a test asks for it.
  // datagram_records_ sits behind the same mutex as the CONNECT list.  The
  // rest are atomics: a test reads them while the pump is still running.
  // udp_port_ is the BND.PORT this relay answered an ASSOCIATE with, zero
  // until one is granted; the address is always listen_addr_, because the
  // socket binds to loopback and to nothing else.
  bool udp_relay_enabled_ = false;
  std::vector<socks5_datagram_record> datagram_records_;
  std::atomic<std::size_t> datagrams_echoed_{0};
  std::atomic<std::size_t> fragments_dropped_{0};
  std::atomic<std::size_t> malformed_dropped_{0};
  std::atomic<std::uint16_t> udp_port_{0};
  std::atomic<std::size_t> echo_failures_{0};
};

} // namespace e2e

#endif // ENCAPSULE_E2E_SOCKS5_TEST_SERVER
