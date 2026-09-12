// Tests for src/injector/server.hpp -- the first test target that includes it.
//
// What is pinned is the two policies M1-a introduced, because both are quiet
// failures: a future edit that reaches for forget_token() again on the loss
// path re-introduces mass amnesia (every resident capsule that ever drops its
// control connection is then refused forever), and an edit that drops the cap
// on the kept set turns a long-running GUI into a token store that only grows.
// Neither shows up on screen -- the UI still lists the pid as injected while
// the capsule spins on reconnect -- so it is pinned here instead.
//
// Deliberately NO transport.  Both policies are decisions a function makes
// about a pid, and both are reachable without a peer: kept_bootstraps is a
// plain record, and injector_server::open()/remove()/close() are what
// injectee_session::process() and ::stop() call.  So the scenarios drive those
// functions with a stub session and ask the server's own question
// -- injector::token_matches() over a real hello message -- to answer whether
// a capsule that walks back in would be let in.  A fake socket, a fake
// acceptor and a pumped io_context would add nothing that a wrong policy
// could not also satisfy, and would make the flaky part of this test the part
// that is not under test.  The live version of the same walk is e2e, which
// owns real injection.

#include <server.hpp>

#include "test_support.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace {

using token_t = injector::injection_token;

// A bootstrap of the real shape: port_mapping_token_size bytes, the length
// token_matches() insists on.  Distinct per pid, so "kept" and "the kept one
// for THIS pid" cannot be confused.
token_t mk(std::uint64_t seed) {
  return token_t{static_cast<unsigned char>(seed & 0xff),
                 static_cast<unsigned char>((seed >> 8) & 0xff), 3, 4, 5, 6,
                 7, 8};
}

// The question the server asks an arriving capsule, built the way the
// injectee builds it (client.hpp: the hello carries the pid and the token it
// fixed at construction) and answered the way process() answers it.  Every
// "would it be let back in?" below goes through here -- nothing re-implements
// the check.
bool accepted(DWORD pid, const token_t &token) {
  InjecteeMessage hello = create_message<InjecteeMessage, "pid">(pid);
  hello["token"_f] = token;
  return injector::token_matches(pid, hello["token"_f]);
}

// A registered session with no socket behind it.  stop() is the seam: the
// real injectee_session::stop(end) hands `end` straight to
// server_.remove(pid_, end), so this does the same and remembers what it was
// passed -- which is how injector_server::close()'s intent is pinned without
// a transport.
struct stub_session : injectee_client {
  asio::io_context io;
  injector_server *server = nullptr;
  DWORD pid = 0;
  session_end seen = session_end::lost;
  int stops = 0;

  void stop(session_end end) override {
    seen = end;
    ++stops;
    server->remove(pid, end);
  }

  // Never driven here; both exist to satisfy the interface the server holds.
  asio::awaitable<void> config(const InjectorConfig &) override { co_return; }
  asio::any_io_executor get_context() override { return io.get_executor(); }
};

// Registers exactly as process_pid() does -- open(pid, ptr) -- and hands back
// the caller's own reference, which is also what keeps the stub alive after
// the table drops it.
std::shared_ptr<stub_session> connect(injector_server &server, DWORD pid) {
  auto ptr = std::make_shared<stub_session>();
  ptr->server = &server;
  ptr->pid = pid;
  const bool opened =
      server.open(pid, std::static_pointer_cast<injectee_client>(ptr));
  CHECK(opened);
  return ptr;
}

// ---------------------------------------------------------------- the seam

// M1, the bug the seam exists for: a control connection that drops is not an
// un-inject.  The session leaves the table, the bootstrap stays, and the same
// capsule walking back in with the token it still holds is let in.
void a_lost_session_keeps_the_bootstrap_and_a_re_registration_lands() {
  injector_server server;
  server.set_port(1234);

  constexpr DWORD pid = 41000;
  const token_t token = mk(pid);
  injector::remember_token(pid, token);
  CHECK(accepted(pid, token));

  auto session = connect(server, pid);
  CHECK(server.clients.size() == 1);
  CHECK(server.kept.size() == 0);  // live: nothing to remember yet

  session->stop(session_end::lost);  // what reader()'s catch passes
  CHECK(server.clients.size() == 0);  // the session really is gone...
  CHECK(accepted(pid, token));        // ...the bootstrap is not
  CHECK(server.kept.size() == 1);

  // The capsule's next hello, same pid, same token: registered again.
  auto again = connect(server, pid);
  CHECK(server.clients.size() == 1);
  CHECK(accepted(pid, token));
  CHECK(server.kept.size() == 0);  // and out of the record while live
}

// The other ending, unchanged by M1-a: the front end closed it, so the
// injection is over and the token goes with it.
void an_un_inject_retires_the_bootstrap() {
  injector_server server;
  server.set_port(1234);

  constexpr DWORD pid = 41100;
  const token_t token = mk(pid);
  injector::remember_token(pid, token);
  auto session = connect(server, pid);

  CHECK(server.close(pid));                // the un-inject button
  CHECK(session->seen == session_end::retired);  // close() means retire
  CHECK(session->stops == 1);              // and stops the session once
  CHECK(server.clients.size() == 0);
  CHECK(server.kept.size() == 0);          // never recorded in the first place
  CHECK(!accepted(pid, token));            // retired: a later hello is refused
  CHECK(!server.close(pid));               // idempotent on a dead pid
}

// A lost session also leaves no second record when it loses twice, and a
// refused hello -- which never registered -- must not retire anything.
void losing_the_same_pid_twice_keeps_one_record() {
  injector_server server;
  server.set_port(1);

  constexpr DWORD pid = 41200;
  injector::remember_token(pid, mk(pid));
  CHECK(!server.remove(pid, session_end::lost));  // no session was registered
  CHECK(!server.remove(pid, session_end::lost));
  CHECK(server.kept.size() == 1);
}

// ------------------------------------------------------------- the keep set

// The record is bounded, and what an overflow retires is the pid that has
// been away longest -- not the one that just arrived.
void the_keep_set_is_capped_and_evicts_the_oldest() {
  injector_server server;
  server.set_port(1);

  constexpr DWORD first = 100000;
  for (DWORD pid = first; pid < first + kept_bootstraps::cap + 1; ++pid) {
    injector::remember_token(pid, mk(pid));
    server.remove(pid, session_end::lost);
  }

  CHECK(server.kept.size() == kept_bootstraps::cap);  // one eviction, no more
  CHECK(!accepted(first, mk(first)));   // the oldest away is the one retired
  CHECK(accepted(first + 1, mk(first + 1)));
  CHECK(accepted(first + kept_bootstraps::cap,        // and the newest,
                 mk(first + kept_bootstraps::cap)));  // which just arrived,
                                                      // is kept
}

// Re-losing a pid refreshes it: it was the eviction candidate, now the one
// behind it is.  This is the case that a "just keep the first N" or a
// "evict whoever is newest" mistake both fail.
void re_losing_a_pid_moves_it_to_the_new_end() {
  injector_server server;
  server.set_port(1);

  constexpr DWORD base = 200000;
  const DWORD away = base;          // loses first, so oldest
  const DWORD runner_up = base + 1; // becomes the oldest once away is refreshed

  injector::remember_token(away, mk(away));
  server.remove(away, session_end::lost);
  for (DWORD pid = base + 1; pid < base + kept_bootstraps::cap; ++pid) {
    injector::remember_token(pid, mk(pid));
    server.remove(pid, session_end::lost);
  }
  CHECK(server.kept.size() == kept_bootstraps::cap);  // exactly full, quiet
  CHECK(accepted(away, mk(away)));                     // not evicted yet

  server.remove(away, session_end::lost);              // lost again: refreshed
  CHECK(server.kept.size() == kept_bootstraps::cap);

  const DWORD newcomer = base + kept_bootstraps::cap;  // one past the brim
  injector::remember_token(newcomer, mk(newcomer));
  server.remove(newcomer, session_end::lost);

  CHECK(!accepted(runner_up, mk(runner_up)));  // the stalest went, not away
  CHECK(accepted(away, mk(away)));             // refreshed, so it stayed
  CHECK(accepted(newcomer, mk(newcomer)));
  CHECK(server.kept.size() == kept_bootstraps::cap);
}

// open() drops the pid from the record, so a capsule that is registered right
// now can never be the victim of an unrelated storm of losses.
void a_live_pid_is_never_eviction_fodder() {
  injector_server server;
  server.set_port(1);

  constexpr DWORD base = 300000;
  const token_t live = mk(base);
  injector::remember_token(base, live);
  auto session = connect(server, base);

  for (DWORD pid = base + 1; pid < base + kept_bootstraps::cap + 64; ++pid) {
    injector::remember_token(pid, mk(pid));
    server.remove(pid, session_end::lost);
  }

  CHECK(server.kept.size() == kept_bootstraps::cap);
  CHECK(server.clients.size() == 1);  // the live session is untouched...
  CHECK(accepted(base, live));        // ...and so is its bootstrap

  session->stop(session_end::retired);  // cleanup: it is a real pid here
  CHECK(!accepted(base, live));
}

// Keeping is not the same as weakening: the remembered bootstrap only ever
// answers to its own token, and a pid that was never published answers to
// nobody.  This is what makes the record safe to keep at all.
void a_kept_bootstrap_is_still_not_a_skeleton_key() {
  injector_server server;
  server.set_port(1);

  constexpr DWORD pid = 41300;
  injector::remember_token(pid, mk(pid));
  auto session = connect(server, pid);
  session->stop(session_end::lost);
  CHECK(accepted(pid, mk(pid)));      // kept, for the capsule that holds it
  CHECK(!accepted(pid, mk(pid + 1))); // a different token is still refused

  // A hello with no token field at all: refused, fail closed.
  InjecteeMessage bare = create_message<InjecteeMessage, "pid">(pid);
  CHECK(!injector::token_matches(pid, bare["token"_f]));

  CHECK(!accepted(41999, mk(41999)));  // a pid nobody ever injected
}

} // namespace

int main() {
  RUN(a_lost_session_keeps_the_bootstrap_and_a_re_registration_lands);
  RUN(an_un_inject_retires_the_bootstrap);
  RUN(losing_the_same_pid_twice_keeps_one_record);
  RUN(the_keep_set_is_capped_and_evicts_the_oldest);
  RUN(re_losing_a_pid_moves_it_to_the_new_end);
  RUN(a_live_pid_is_never_eviction_fodder);
  RUN(a_kept_bootstrap_is_still_not_a_skeleton_key);

  return test_failures;
}
