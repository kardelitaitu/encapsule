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
#include <atomic>
#include <cstdio>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

using tcp = asio::ip::tcp;

struct injectee_client {
  virtual ~injectee_client() {}

  virtual void stop() = 0;
  virtual asio::awaitable<void> config(const InjectorConfig &) = 0;
  virtual asio::any_io_executor get_context() = 0;
};

using injectee_client_ptr = std::shared_ptr<injectee_client>;

// The pid -> session table, with its own lock inside it.
//
// C1: this map really is touched from two threads at once.  Sessions register
// and unregister on the io_context thread - injectee_session::process() calls
// open() and injectee_session::stop() calls remove() - while the front end
// reads the very same map from its own thread: the CLI runs io_context::run()
// on a jthread in do_inject() and then calls enable_log()/set_proxy()/inject()
// from main, and the GUI detaches do_server() on a thread of its own while the
// elements app thread calls inject()/close()/set_proxy()/enable_log() out of
// the button and toggle handlers.  An emplace or erase that rebalances
// the red-black tree underneath an in-flight broadcast_config() loop is
// undefined behavior; in a Release build it is a wild pointer, in a debug
// iterator build it is a "map/set iterator not incrementable" abort.
//
// A lock was chosen over "post every mutation to the io executor" because
// inject() has to answer "is this pid already injected?" synchronously on the
// caller's thread, and it is also called *from* the io_context thread, by
// process()'s subprocess enumeration and its subpid reply - a post-and-wait
// there self-deadlocks.  The io_context also is not a member of
// injector_server, so it could not be posted to from here at all.
//
// The mutex lives in the table rather than next to it on purpose: `clients`
// has to stay reachable as a public member - injectee_session_cli::
// process_close() reads server_.clients.size() to decide whether any client is
// left - and a lock that sits beside a public map is a lock that public code
// can walk past.  Every operation here is short, non-blocking and returns a copy
// (a bool, a size, or a shared_ptr), so no caller can hold the lock while it
// calls into asio, and nothing here co_awaits at all.
//
// Lock order: config_mutex -> this lock, never the reverse.  Every config_*()
// setter on injector_server holds config_mutex and then walks the table (via
// broadcast_config()), so this lock is by design the inner one; nothing that
// holds it ever touches config_ or config_mutex, which keeps the reverse edge
// out of the file.
class injector_clients {
public:
  // Registers a session; false when the pid is already in (the old emplace
  // contract, kept because open()'s result decides stop()'s unhook path).
  bool insert(DWORD pid, injectee_client_ptr ptr) {
    std::lock_guard guard(mtx);
    return clients.emplace(pid, std::move(ptr)).second;
  }

  bool contains(DWORD pid) const {
    std::lock_guard guard(mtx);
    return clients.contains(pid);
  }

  // A copy of one entry, or null.  The caller uses the pointer after the lock
  // is gone - close() must not call stop() under it, because stop() comes
  // straight back into erase().
  injectee_client_ptr find(DWORD pid) const {
    std::lock_guard guard(mtx);
    if (auto iter = clients.find(pid); iter != clients.end()) {
      return iter->second;
    }
    return nullptr;
  }

  bool erase(DWORD pid) {
    std::lock_guard guard(mtx);
    return clients.erase(pid) != 0;
  }

  // The snapshot broadcast_config() sends to: shared_ptr copies taken under
  // the lock, co_spawn done outside it.
  std::vector<injectee_client_ptr> snapshot() const {
    std::vector<injectee_client_ptr> out;
    std::lock_guard guard(mtx);
    out.reserve(clients.size());
    for (const auto &[_, client] : clients) {
      out.push_back(client);
    }
    return out;
  }

  std::size_t size() const {
    std::lock_guard guard(mtx);
    return clients.size();
  }

private:
  mutable std::mutex mtx;
  std::map<DWORD, injectee_client_ptr> clients;
};

struct injector_server {
  injector_clients clients;
  InjectorConfig config_;
  std::mutex config_mutex;

  std::uint16_t port_ = -1;

  void set_port(std::uint16_t port) { port_ = port; }

  // Note the check and the injection are not one atomic step: two threads
  // that race to inject the same pid can both get past contains().  That is
  // pre-existing and deliberate - the callers are a user clicking a button or
  // a wildcard sweep over a snapshot of the process list, and closing the
  // window would mean holding this lock across VirtualAllocEx/
  // CreateRemoteThread, i.e. into the kernel, which is exactly what the lock
  // discipline above forbids.
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
    return clients.insert(pid, std::move(ptr));
  }

  // Called with config_mutex held (every config_*() setter does), which is why
  // the order is config_mutex -> clients' lock.  The config is copied once and
  // the sessions are copied out as a snapshot, so the table's lock is already
  // dropped by the time asio is entered.
  void broadcast_config() {
    InjectorConfig cfg = config_;
    for (const injectee_client_ptr &client : clients.snapshot()) {
      asio::co_spawn(
          client->get_context(),
          [cfg, client] { return client->config(cfg); },
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

    return clients.erase(pid);
  }

  bool close(DWORD pid) {
    injectee_client_ptr client = clients.find(pid);
    if (!client) {
      return false;
    }

    // Unlocked: stop() closes the socket and re-enters the table through
    // remove(), so doing it under the table's lock would be a self-deadlock.
    client->stop();
    return true;
  }
};

struct injectee_session : injectee_client,
                          std::enable_shared_from_this<injectee_session> {
  tcp::socket socket_;
  asio::steady_timer timer_;
  injector_server &server_;
  DWORD pid_;
  // Registered with the server, so it owns a client and owes an unhook.
  // Atomic because stop() runs on whichever thread noticed the loss: the
  // io_context thread (reader() failing, process() refusing the token) or,
  // since C1, the front-end thread that called close().  Release/acquire on
  // the one thread that wins the exchange is also what makes pid_ visible to
  // it, so exactly one thread runs the teardown once.
  std::atomic<bool> opened_ = false;

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
    // unverified connection could otherwise switch the tool off.  The
    // exchange covers the second case too, a close() from the front end
    // racing the reader() of the same session: only the winner removes and
    // only the winner runs the hook.
    if (!opened_.exchange(false)) {
      return;
    }

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
