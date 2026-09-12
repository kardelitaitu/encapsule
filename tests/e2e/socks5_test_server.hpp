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

// A header-only, no-auth socks5 CONNECT relay for the end-to-end smoke test.
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
// THREADING: one worker thread, one session at a time, all I/O polled with a
// bounded idle timeout so ~socks5_test_server() never hangs.  That is plenty
// for a decoy that opens one connection, exchanges a sentinel and closes.
//
// NOTE: <socks5.hpp> has NO include guard and defines functions, so this
// header must be included by exactly one translation unit (e2e_test.cpp).

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

  // Decide the reply for each CONNECT; return SOCKS_SUCCESS to let the
  // echo-loop start, anything else to refuse the request.  Set it before
  // spawning the client; the hook must not outlive the server.
  void set_on_connect(hook_type hook) {
    std::lock_guard<std::mutex> guard(mutex_);
    on_connect_ = std::move(hook);
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
    const char chosen[2] = {SOCKS_VERSION, SOCKS_NO_AUTHENTICATION};
    if (!write_all(sock, chosen, sizeof(chosen))) {
      return;
    }

    char head[4] = {};
    if (!read_exact(sock, head, 4, kHandshakeIdleMs)) {
      return;
    }
    if (head[0] != SOCKS_VERSION || head[1] != SOCKS_CONNECT) {
      return; // BIND/UDP are out of scope for this relay
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

  void record(const request &rec) {
    std::lock_guard<std::mutex> guard(mutex_);
    records_.push_back(rec);
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
  std::atomic<std::size_t> echoed_round_trips_{0};
  std::atomic<std::size_t> echoed_bytes_{0};
};

} // namespace e2e

#endif // ENCAPSULE_E2E_SOCKS5_TEST_SERVER
