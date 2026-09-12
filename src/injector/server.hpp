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

#ifndef ENCAPSULE_INJECTOR_SERVER
#define ENCAPSULE_INJECTOR_SERVER

#include "async_io.hpp"
#include "injector.hpp"
#include "schema.hpp"
#include <asio.hpp>
#include <cstdio>
#include <map>
#include <mutex>
#include <optional>

using tcp = asio::ip::tcp;

struct injectee_client {
  virtual ~injectee_client() {}

  virtual void stop() = 0;
  virtual asio::awaitable<void> config(const InjectorConfig &) = 0;
  virtual asio::any_io_executor get_context() = 0;
};

using injectee_client_ptr = std::shared_ptr<injectee_client>;

struct injector_server {
  std::map<DWORD, injectee_client_ptr> clients;
  InjectorConfig config_;
  std::mutex config_mutex;

  std::uint16_t port_ = -1;

  void set_port(std::uint16_t port) { port_ = port; }

  bool inject(DWORD pid) {
    if (port_ == -1) {
      return false;
    }
    if (clients.contains(pid)) {
      return false;
    } else {
      return injector::inject(pid, port_);
    }
  }

  bool open(DWORD pid, injectee_client_ptr ptr) {
    return clients.emplace(pid, ptr).second;
  }

  void broadcast_config() {
    for (const auto &[_, client] : clients) {
      asio::co_spawn(
          client->get_context(),
          [cfg = config_, client] { return client->config(cfg); },
          asio::detached);
    }
  }

  template <typename T> void config_proxy(T &&v) {
    std::lock_guard guard(config_mutex);
    config_["addr"_f] = std::forward<T>(v);

    broadcast_config();
  }

  void set_proxy(const ip::address &addr, std::uint32_t port) {
    config_proxy(from_asio(addr, port));
  }

  void clear_proxy() { config_proxy(std::nullopt); }

  // The credentials of P5, kept in the same config the proxy address lives
  // in, and set the same way: take the lock, write the field, push the result
  // to every session already connected.  Both arguments are optional and
  // separate because the wire says so (schema.hpp): a field that is not set
  // adds no bytes at all, which is what "no authentication offered" means, so
  // a value that is not present is left exactly as it was -- encoding an empty
  // std::string instead would emit a length-only field, a different request on
  // the wire that no user asked for.  Dropping a credential that is already
  // there is what clear_proxy_credentials() is for.
  void set_proxy_credentials(std::optional<std::string> username,
                             std::optional<std::string> password) {
    std::lock_guard guard(config_mutex);

    if (username) {
      config_["username"_f] = std::move(*username);
    }
    if (password) {
      config_["password"_f] = std::move(*password);
    }

    broadcast_config();
  }

  // Back to "nothing offered": both fields are erased, not emptied, so the
  // config encodes byte-for-byte what a credential-free injector always did.
  void clear_proxy_credentials() {
    std::lock_guard guard(config_mutex);

    config_["username"_f] = std::nullopt;
    config_["password"_f] = std::nullopt;

    broadcast_config();
  }

  void enable_log(bool enable = true) {
    std::lock_guard guard(config_mutex);
    config_["log"_f] = enable;

    broadcast_config();
  }

  void disable_log() { enable_log(false); }

  void enable_subprocess(bool enable = true) {
    std::lock_guard guard(config_mutex);
    config_["subprocess"_f] = enable;

    broadcast_config();
  }

  void disable_subprocess() { enable_subprocess(false); }

  InjectorConfig get_config() {
    std::lock_guard guard(config_mutex);
    return config_;
  }

  bool remove(DWORD pid) {
    // The injection is over, so its token is no longer worth keeping.
    injector::forget_token(pid);

    if (auto iter = clients.find(pid); iter != clients.end()) {
      clients.erase(iter);
      return true;
    }

    return false;
  }

  bool close(DWORD pid) {
    if (auto iter = clients.find(pid); iter != clients.end()) {
      iter->second->stop();
      return true;
    }

    return false;
  }
};

struct injectee_session : injectee_client,
                          std::enable_shared_from_this<injectee_session> {
  tcp::socket socket_;
  asio::steady_timer timer_;
  injector_server &server_;
  DWORD pid_;
  bool opened_ = false; // registered with the server, so it owns a client

  injectee_session(tcp::socket socket, injector_server &server)
      : socket_(std::move(socket)), timer_(socket_.get_executor()),
        server_(server), pid_(0) {
    timer_.expires_at(std::chrono::steady_clock::time_point::max());
  }

  void start() {
    asio::co_spawn(
        socket_.get_executor(),
        [self = shared_from_this()] { return self->reader(); }, asio::detached);
  }

  asio::any_io_executor get_context() { return socket_.get_executor(); }

  asio::awaitable<void> config(const InjectorConfig &cfg) {
    co_await async_write_message(
        socket_, create_message<InjectorMessage, "config">(cfg));
  }

  asio::awaitable<void> reader() {
    try {
      while (true) {
        auto msg = co_await async_read_message<InjecteeMessage>(socket_);
        asio::co_spawn(
            socket_.get_executor(),
            [self = shared_from_this(), msg = std::move(msg)] {
              return self->process(msg);
            },
            asio::detached);
      }
    } catch (std::exception &) {
      stop();
    }
  }

  virtual asio::awaitable<void> process_pid() { co_return; }
  virtual asio::awaitable<void> process_connect(const InjecteeConnect &msg) {
    co_return;
  }
  virtual asio::awaitable<void> process_subpid(std::uint16_t pid, bool result) {
    co_return;
  }
  virtual void process_close() {}

  asio::awaitable<void> process(const InjecteeMessage &msg) {
    if (auto v = compare_message<"pid">(msg)) {
      // P4-3: the injectee proves itself with the token that went into its
      // mapping payload.  No field, a foreign sequence, or a pid nobody ever
      // injected all refuse the session before it is registered.
      if (!injector::token_matches(*v, msg["token"_f])) {
        std::fprintf(stderr,
                     "encapsule: refused pid %lu, no valid injection token\n",
                     static_cast<unsigned long>(*v));
        std::fflush(stderr);
        stop();
        co_return;
      }

      pid_ = *v;
      opened_ = server_.open(pid_, shared_from_this());
      auto config_ = server_.get_config();
      if (config_["subprocess"_f] && *config_["subprocess"_f]) {
        enumerate_child_pids(pid_, [this](DWORD pid) { server_.inject(pid); });
      }
      co_await config(config_);
      co_await process_pid();
    } else if (auto v = compare_message<"connect">(msg)) {
      co_await process_connect(*v);
    } else if (auto v = compare_message<"subpid">(msg)) {
      co_await process_subpid(*v, server_.inject(*v));
    }
  }

  void stop() {
    socket_.close();
    timer_.cancel();

    // A session that was never registered - typically one refused above -
    // has nothing to unhook, and must not reach process_close(): that hook
    // ends the whole injector once its last client is gone, so an
    // unverified connection could otherwise switch the tool off.
    if (!opened_) {
      return;
    }

    opened_ = false;
    server_.remove(pid_);
    process_close();
  }
};

template <typename Session = injectee_session>
asio::awaitable<void> listener(tcp::acceptor acceptor, auto &&...args) {
  for (;;) {
    std::make_shared<Session>(
        co_await acceptor.async_accept(asio::use_awaitable),
        std::forward<decltype(args)>(args)...)
        ->start();
  }
}

#endif
