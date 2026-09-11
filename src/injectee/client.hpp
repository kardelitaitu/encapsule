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

#ifndef PROXINJECT_INJECTEE_CLIENT
#define PROXINJECT_INJECTEE_CLIENT

#include "async_io.hpp"
#include "queue.hpp"
#include "schema.hpp"
#include "winnet.hpp"
#include <algorithm>
#include <chrono>
#include <vector>

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
  InjectorConfig get() {
    std::lock_guard guard(mtx);
    return live ? cfg : pinned;
  }

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
