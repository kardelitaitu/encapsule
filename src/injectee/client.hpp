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

#ifndef ENCAPSULE_INJECTEE_CLIENT
#define ENCAPSULE_INJECTEE_CLIENT

#include "async_io.hpp"
#include "queue.hpp"
#include "schema.hpp"
#include "utils.hpp"
#include "winnet.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <optional>
#include <string_view>
#include <vector>

// One hooked call's slice of the routing config: the decision material a
// detour needs, as a value that wipes itself.
//
// Why this exists when InjectorConfig does not: InjectorConfig is a protopuf
// message holding the socks5 username and password as std::strings, and all
// five hook sites used to take a whole by-value copy of one, per call.  A copy
// of a secret nobody scrubs is a plaintext login sitting in a stack frame
// until that frame is recycled -- inside a foreign process, reachable by any
// same-user debugger with ReadProcessMemory -- and it was made once per
// connection.  This carries the same material, and its destructor zeroes what
// it holds.
//
// The credential slots are fixed arrays rather than strings for exactly that
// second reason: a destructor can zero the octets of an array it CONTAINS, but
// not a heap buffer a std::string points at -- the string hands that buffer
// back unzeroed when it dies.  The capacity is the front ends' own cap
// (utils.hpp, proxy_credential_max_length), which parse_proxy_url enforces on
// the way in, so nothing a supported proxy login can carry is truncated here;
// were the two caps ever pulled apart, the copy would truncate and the proxy
// would refuse the login -- loud, not silent.
struct injectee_route {
  static constexpr size_t credential_max = proxy_credential_max_length;

  // The proxy endpoint; absent means nothing to route AND nothing to refuse,
  // which is the test every connect site makes before it branches (F1).
  std::optional<IpAddr> proxy;
  bool log = false;
  bool subprocess = false;

  injectee_route() = default;
  // No copies.  A type whose job is to own one plaintext login cannot afford
  // an unscrubbed twin of itself; moving is allowed, and it wipes the source.
  injectee_route(const injectee_route &) = delete;
  injectee_route &operator=(const injectee_route &) = delete;
  injectee_route(injectee_route &&other) noexcept
      : proxy(std::move(other.proxy)), log(other.log),
        subprocess(other.subprocess), username_size_(other.username_size_),
        password_size_(other.password_size_) {
    memcpy(username_, other.username_, username_size_);
    memcpy(password_, other.password_, password_size_);
    SecureZeroMemory(other.username_, sizeof other.username_);
    SecureZeroMemory(other.password_, sizeof other.password_);
    other.username_size_ = 0;
    other.password_size_ = 0;
  }

  ~injectee_route() {
    // SecureZeroMemory, not memset: nothing reads these bytes after this
    // point, and a provably-unread fill is the one MSVC elides.
    SecureZeroMemory(username_, sizeof username_);
    SecureZeroMemory(password_, sizeof password_);
  }

  // Views into this object, for the handshake that runs in the frame holding
  // it -- which is why they cannot outlive what they point at.
  std::string_view username() const { return {username_, username_size_}; }
  std::string_view password() const { return {password_, password_size_}; }

 private:
  friend struct injectee_config;  // only the config fills a route

  char username_[credential_max + 1] = {};
  char password_[credential_max + 1] = {};
  size_t username_size_ = 0;
  size_t password_size_ = 0;
};

// The routing config the winsock hooks consult, plus the fail-closed copy.
//
// pinned is the last config that arrived on a live session, and it is never
// cleared.  Once the IPC channel is gone the victim keeps being routed to the
// last known proxy instead of silently going out direct (P4 #5): a proxy that
// died in the meantime simply fails every connect, which is honest, while a
// quiet direct route is exactly the leak the user installed this to avoid.
struct injectee_config {
  InjectorConfig cfg;
  InjectorConfig pinned;
  bool live = false; // a session is up and has delivered a config
  std::mutex mtx;

  void set(const InjectorConfig &config) {
    std::lock_guard guard(mtx);
    cfg = config;
    pinned = config;
    live = true;
  }

  // What the hooks route by: the live config while a session is up, the
  // pinned one for as long as it is not.
  //
  // Three rules this keeps, and one it deliberately does not need:
  //   * the lock covers the extract below and nothing else.  It is NOT carried
  //     into the connect: a proxied handshake can sit out
  //     SOCKS_HANDSHAKE_TIMEOUT_MS (3s), and pushing a new proxy while a
  //     connection is wedged is precisely what a user does, so a borrow that
  //     kept mtx would freeze set_proxy_credentials/clear_proxy_credentials
  //     for that long.  What leaves the lock is a value.
  //   * that value owns everything it exposes -- an IpAddr and two fixed
  //     arrays -- so no reference handed out from here can outlive this object.
  //   * what does have to outlive the call is the injectee_config itself, and
  //     that is not bought by the acquire load.  C4's review said it plainly:
  //     lifetime here comes from RESIDENCY -- injectee.cpp C2 never unmaps the
  //     module and nothing ever unbinds these globals, not even give_up() --
  //     so load_scope(config) cannot return a dead object.  A route built a
  //     moment before any future retire path is still safe, because it owns
  //     its bytes; the pointer read that made it would not be, and that is the
  //     day this comment becomes load-bearing.
  injectee_route get() {
    std::lock_guard guard(mtx);
    const InjectorConfig &src = live ? cfg : pinned;

    injectee_route route;
    route.proxy = src["addr"_f];
    route.log = src["log"_f].value_or(false);
    route.subprocess = src["subprocess"_f].value_or(false);
    copy_credential(route.username_, route.username_size_,
                    sizeof route.username_, src["username"_f]);
    copy_credential(route.password_, route.password_size_,
                    sizeof route.password_, src["password"_f]);
    return route;
  }

 private:
  // optional<string> into a fixed array plus its length, under the lock the
  // caller already holds.  The terminating NUL the array was zero-initialised
  // with survives past the length, so a view out of here is never unterminated.
  template <typename Opt>
  static void copy_credential(char *dst, size_t &size, size_t room,
                              const Opt &value) {
    if (!value) {
      return;
    }
    const auto &text = *value;
    size = (std::min)(text.size(), room - 1);
    memcpy(dst, text.data(), size);
  }

 public:

  // The channel went away.  This only marks the session down; clearing the
  // config here was the fail-open this replaces.
  void drop() {
    std::lock_guard guard(mtx);
    live = false;
  }
};

// One instance per injected process, for the lifetime of that process: losing
// the injector does not end it, it enters reconnect mode (bounded exponential
// backoff on timer_) with the hooks still installed and the routing still
// pinned.  It never unloads the DLL - the unloader this replaces freed DLL
// code out from under other threads' detours.
struct injectee_client : std::enable_shared_from_this<injectee_client> {
  using clock_type = asio::steady_timer::clock_type;

  static constexpr std::chrono::milliseconds kBackoffStart{1000};
  static constexpr std::chrono::milliseconds kBackoffCap{10000};
  static constexpr std::chrono::milliseconds kReconnectBudget{60000};

  tcp::socket socket_;
  asio::any_io_executor executor_;
  tcp::endpoint endpoint_;
  asio::steady_timer timer_;
  blocking_queue<InjecteeMessage> &queue_;
  injectee_config &config_;
  // Read out of the IPC mapping payload and echoed back with the
  // introduction; the control server refuses a session without it (P4-3).
  std::vector<unsigned char> token_;

  std::chrono::milliseconds backoff_ = kBackoffStart;
  clock_type::time_point deadline_{};
  bool reconnecting_ = false;

  injectee_client(asio::io_context &io_context, const tcp::endpoint &endpoint,
                  blocking_queue<InjecteeMessage> &queue,
                  injectee_config &config,
                  const std::vector<unsigned char> &token = {})
      : socket_(io_context), executor_(io_context.get_executor()),
        endpoint_(endpoint), timer_(io_context), queue_(queue),
        config_(config), token_(token) {
    timer_.expires_at((clock_type::time_point::max)());
  }

  asio::awaitable<void> start() {
    try {
      co_await open_session();
    } catch (const std::exception &) {
      // The injector went before we ever shook hands: same policy as a
      // mid-session loss, keep the hooks, keep the config, retry.
      stop();
      begin_reconnect();
      co_return;
    }

    asio::co_spawn(executor_, reader(), asio::detached);
    asio::co_spawn(executor_, writer(), asio::detached);
  }

  // Connect and introduce ourselves.  The hello re-presents the token, so a
  // reconnect is authenticated exactly like a first session.
  asio::awaitable<void> open_session() {
    socket_ = tcp::socket(executor_);
    co_await socket_.async_connect(endpoint_, asio::use_awaitable);

    InjecteeMessage hello =
        create_message<InjecteeMessage, "pid">(GetCurrentProcessId());
    hello["token"_f] = token_;

    co_await async_write_message(socket_, hello);
  }

  asio::awaitable<void> reader() {
    try {
      while (true) {
        auto msg = co_await async_read_message<InjectorMessage>(socket_);
        asio::co_spawn(
            executor_,
            [this, msg = std::move(msg)] { return process(msg); },
            asio::detached);
      }
    } catch (std::exception &) {
      stop();
      begin_reconnect();
    }
  }

  asio::awaitable<void> writer() {
    try {
      while (true) {
        InjecteeMessage msg = co_await queue_.pop();
        co_await async_write_message(socket_, msg);
      }
    } catch (std::exception &) {
      stop();
      begin_reconnect();
    }
  }

  asio::awaitable<void> process(const InjectorMessage &msg) {
    if (auto v = compare_message<"config">(msg)) {
      config_.set(*v); // the fresh config also becomes the new pin
    }

    co_return;
  }

  // ---- reconnect: bounded exponential backoff on the existing timer_ ----

  void begin_reconnect() {
    if (reconnecting_) {
      return; // reader() and writer() both notice the same lost session
    }
    reconnecting_ = true;
    backoff_ = kBackoffStart;
    deadline_ = clock_type::now() + kReconnectBudget;
    arm(backoff_);
  }

  void arm(std::chrono::milliseconds delay) {
    timer_.expires_after(delay);
    timer_.async_wait([this](const asio::error_code &ec) {
      if (ec) {
        return; // cancelled: a session is up again
      }
      asio::co_spawn(executor_, attempt(), asio::detached);
    });
  }

  asio::awaitable<void> attempt() {
    try {
      co_await open_session();
    } catch (const std::exception &) {
      close_socket();
      if (clock_type::now() >= deadline_) {
        give_up();
      } else {
        backoff_ = (std::min)(backoff_ * 2, kBackoffCap);
        arm(backoff_);
      }
      co_return;
    }

    // Back.  Routing does not leave the pinned config behind until the
    // injector has actually pushed a fresh one (injectee_config::set).
    reconnecting_ = false;
    backoff_ = kBackoffStart;
    asio::co_spawn(executor_, reader(), asio::detached);
    asio::co_spawn(executor_, writer(), asio::detached);
  }

  // Out of budget.  Stay resident: park the io_context on a timer that never
  // expires, so do_client() never returns, the globals the hooks read stay
  // bound, the detours keep pointing at mapped code, and routing stays pinned
  // to the last proxy.  Unloading here was the use-after-free.
  void give_up() { timer_.expires_at((clock_type::time_point::max)()); }

  void close_socket() {
    asio::error_code ec;
    socket_.close(ec);
  }

  // The session is gone: stop using it, keep everything that decides routing.
  // The timer is deliberately not cancelled - the reconnect schedule owns it.
  void stop() {
    queue_.cancel();
    config_.drop();
    close_socket();
  }
};

#endif
