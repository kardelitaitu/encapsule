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

#include <asio.hpp>

#include "test_support.hpp"

#include <queue.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <condition_variable>
#include <cstdlib>
#include <cstdio>
#include <exception>
#include <memory>
#include <thread>
#include <vector>

// blocking_queue<T> is a std::queue guarded by a channel<void(error_code)>.
// Every scenario below runs on its own io_context ON ITS OWN THREAD and is
// bounded by an alarm armed on the test's main thread, so both a stuck channel
// and a producer call that blocks synchronously fail as a NAMED scenario
// instead of turning into a ctest-level TIMEOUT (see run_scenario).
//
// kScenarioCount x kWatchdogMs + margin is the arithmetic tests/queue/
// CMakeLists.txt uses for common.queue's TIMEOUT, and main() checks
// kScenarioCount against the scenarios it actually ran -- the two numbers are
// coupled by a failing test, not by a comment.
namespace {

constexpr int kWatchdogMs = 8000;
constexpr int kScenarioCount = 12;
constexpr int kItems = 64;
constexpr int kSentinel = -7;

// One scenario: its own io_context, its own io thread, and an alarm that does
// NOT live on that io thread.
//
// That separation is the whole point.  The regression this suite exists to
// catch is a push() that blocks synchronously (a hooked winsock call in a
// foreign process must never wait for a report nobody is reading), and a timer
// armed on the SAME io_context as the blocked call can never fire -- the
// blocked thread is the only thing that would run it.  The previous shape
// therefore turned a wedging producer into the CTest TIMEOUT on common.queue,
// a failure with no scenario name attached.  Here the deadline is a
// condition_variable wait on the test's main thread, which keeps running while
// the io thread is wedged, so the scenario fails BY NAME.
struct scenario_state {
  asio::io_context ctx;
  std::mutex m;
  std::condition_variable cv;
  bool done;                    // guarded by m
  std::exception_ptr error;     // guarded by m
  bool finished;                // written by the main thread only
};

// Scenarios actually started, so main() can prove the TIMEOUT arithmetic in
// tests/queue/CMakeLists.txt still matches the file it is sized for.  Plus the
// scenarios whose io thread had to be abandoned: main() ends the run with
// _Exit() when that count is non-zero (see the note there).
int scenarios_run = 0;
int scenarios_abandoned = 0;

// Runs `body` (an awaitable taking the io_context) on its own io thread until
// it finishes or kWatchdogMs expires, whichever happens first.
template <typename Body>
void run_scenario(const char *name, Body body) {
  // shared_ptr rather than a stack object, because a timed-out io thread is
  // DETACHED and keeps this alive: joining it would reintroduce the very hang
  // the alarm exists to escape.  The leak is deliberate and only ever happens
  // on a scenario that has already failed.
  auto s = std::make_shared<scenario_state>();
  ++scenarios_run;

  asio::co_spawn(s->ctx, body(s->ctx), [s](std::exception_ptr e) {
    {
      std::lock_guard<std::mutex> lock(s->m);
      s->error = e;
      s->done = true;
    }
    s->ctx.stop();
    s->cv.notify_all();
  });

  std::thread io([s] { s->ctx.run(); });

  {
    std::unique_lock<std::mutex> lock(s->m);
    s->finished = s->cv.wait_for(lock, std::chrono::milliseconds(kWatchdogMs),
                                 [s] { return s->done; });
  }

  if (s->finished) {
    io.join();
  } else {
    s->ctx.stop(); // releases a parked loop; useless against a wedged call
    io.detach();   // never join the thread we are about to report as hung
    ++scenarios_abandoned;
  }

  CHECK(s->finished); // the failure is counted here...
  if (!s->finished) { // ...this only names the scenario that produced it
    std::printf("FAIL [%s] still running after %dms -- a producer/consumer is"
                " stuck; named here instead of by the ctest TIMEOUT\n", name,
                kWatchdogMs);
  }

  std::exception_ptr error;
  {
    std::lock_guard<std::mutex> lock(s->m);
    error = s->error;
  }
  CHECK(!error);
  if (error) {
    try {
      std::rethrow_exception(error);
    } catch (const asio::system_error &e) {
      std::printf("  [%s] unexpected asio::system_error %s:%d (%s)\n", name,
                  e.code().category().name(), e.code().value(), e.what());
    } catch (const std::exception &e) {
      std::printf("  [%s] unexpected exception: %s\n", name, e.what());
    } catch (...) {
      std::printf("  [%s] unexpected unknown exception\n", name);
    }
  }
}

// (1) FIFO ordering across N pushes, both when everything fits in the channel
// buffer and when the buffer is far smaller than the item count (the extra
// pushes then wait as pending send operations).
asio::awaitable<void> fifo_order(asio::io_context &ctx) {
  {
    blocking_queue<int> buffered(ctx, kItems);
    for (int i = 0; i < kItems; ++i) {
      buffered.push(i);
    }
    for (int i = 0; i < kItems; ++i) {
      CHECK_EQ(co_await buffered.pop(), i);
    }
  }

  {
    blocking_queue<int> overflowing(ctx, 1);
    for (int i = 0; i < kItems; ++i) {
      overflowing.push(i);
    }
    for (int i = 0; i < kItems; ++i) {
      CHECK_EQ(co_await overflowing.pop(), i);
    }
  }
}

// Drains everything into `out` until the sentinel arrives; a single consumer.
asio::awaitable<void> drain(blocking_queue<int> &q, std::vector<int> &out) {
  while (true) {
    int v = co_await q.pop();
    if (v == kSentinel) {
      break;
    }
    out.push_back(v);
  }
}

// (2) one consumer coroutine (co_spawn'd) drains the queue while the producer
// feeds it; the consumer starts before anything is pushed, so it really does
// block inside pop() and get woken up by each push.
asio::awaitable<void> single_consumer_drains(asio::io_context &ctx) {
  blocking_queue<int> q(ctx, 4);
  std::vector<int> got;
  got.reserve(kItems);

  asio::steady_timer wake(ctx);
  wake.expires_at(asio::steady_timer::time_point::max());
  bool consumer_done = false;
  std::exception_ptr consumer_error;

  asio::co_spawn(ctx, drain(q, got), [&](std::exception_ptr e) {
    consumer_error = e;
    consumer_done = true;
    wake.cancel();
  });

  for (int i = 0; i < kItems; ++i) {
    q.push(i);
    co_await asio::post(ctx, asio::use_awaitable);
  }
  q.push(kSentinel);

  if (!consumer_done) {
    try {
      co_await wake.async_wait(asio::use_awaitable);
    } catch (const asio::system_error &) {
      // expected: the consumer's completion handler cancelled `wake`
    }
  }

  CHECK(consumer_done);
  CHECK(!consumer_error);
  CHECK_EQ(got.size(), static_cast<std::size_t>(kItems));
  for (int i = 0; i < kItems && i < static_cast<int>(got.size()); ++i) {
    CHECK_EQ(got[i], i);
  }
}

// (3) cancel() must release a pop() that is waiting on an empty queue.
// asio 1.22.2 delivers the cancellation through the payload error code of
// channel<void(error_code)>, which use_awaitable turns into a thrown
// asio::system_error -- the code is channel_cancelled, not operation_aborted.
asio::awaitable<void> cancel_wakes_pending_pop(asio::io_context &ctx) {
  blocking_queue<int> q(ctx, 4);

  asio::steady_timer canceller(ctx, std::chrono::milliseconds(20));
  canceller.async_wait([&q](asio::error_code ec) {
    if (!ec) {
      q.cancel();
    }
  });

  bool caught = false;
  asio::error_code code;
  try {
    int v = co_await q.pop();
    (void)v; // a non-throwing pop() is reported by CHECK(caught) below
  } catch (const asio::system_error &e) {
    caught = true;
    code = e.code();
  }

  CHECK(caught);
  CHECK(code == asio::experimental::error::channel_cancelled);
  std::printf("  note: cancel() surfaced %s:%d (%s)\n", code.category().name(),
              code.value(), code.message().c_str());

  // the queue must stay usable after a cancellation
  q.push(1234);
  CHECK_EQ(co_await q.pop(), 1234);
}

// Records what a pop() blocked on an empty queue sees when the queue dies.
asio::awaitable<void> pop_until_closed(blocking_queue<int> &q,
                                       asio::error_code &out, bool &threw) {
  try {
    int v = co_await q.pop();
    threw = false;
    (void)v;
  } catch (const asio::system_error &e) {
    threw = true;
    out = e.code();
  }
}

// (4) destructor safety: ~blocking_queue closes the channel while items are
// still queued and sends are still pending, and while a consumer is blocked.
asio::awaitable<void> destructor_with_pending_items(asio::io_context &ctx) {
  // (a) buffered items plus pending sends, nobody ever pops them
  {
    blocking_queue<int> q(ctx, 2);
    for (int i = 0; i < 8; ++i) {
      q.push(i);
    }
  }
  for (int i = 0; i < 16; ++i) {
    co_await asio::post(ctx, asio::use_awaitable);
  }
  CHECK(true);

  // (b) a consumer parked in pop() must be released by the destructor
  bool released = false;
  asio::error_code code;
  bool threw = false;
  {
    blocking_queue<int> q(ctx, 2);
    asio::co_spawn(ctx, pop_until_closed(q, code, threw),
                   [&released](std::exception_ptr) { released = true; });
    co_await asio::post(ctx, asio::use_awaitable);
  }
  for (int i = 0; i < 16; ++i) {
    co_await asio::post(ctx, asio::use_awaitable);
  }

  CHECK(released);
  CHECK(threw);
  CHECK(code == asio::experimental::error::channel_closed);
}

// (5) capacity: an overflowing bounded queue drops the OLDEST item and counts
// it, so what survives is the newest report -- the one still worth reading.
// No consumer runs here at all, which is the parked-injector shape that made
// M5 unbounded: the bound has to hold with nobody popping.
asio::awaitable<void> overflow_drops_oldest_and_counts(asio::io_context &ctx) {
  constexpr std::size_t cap = 8;
  //  The token channel stays wide on purpose, so every item below is turned
  // away by the QUEUE bound and not by a full channel.
  blocking_queue<int> q(ctx, 1024, cap);

  CHECK_EQ(q.capacity(), cap);
  CHECK_EQ(q.drops(), static_cast<std::size_t>(0));

  for (int i = 0; i < 20; ++i) {
    q.push(i);
  }

  CHECK_EQ(q.size(), cap);
  CHECK_EQ(q.drops(), static_cast<std::size_t>(20 - cap));

  // The twelve that went away were the twelve OLDEST, so 12..19 remain, in
  // order, and the eight tokens behind them still match eight items.
  for (int i = 12; i < 20; ++i) {
    CHECK_EQ(co_await q.pop(), i);
  }

  CHECK_EQ(q.size(), static_cast<std::size_t>(0));
  // eight delivered + twelve dropped + none left == the twenty pushed.
  CHECK_EQ(static_cast<std::size_t>(8) + q.drops() + q.size(),
           static_cast<std::size_t>(20));
}

// (6) cancel() drains what is still queued instead of stranding it, and every
// item it removes is counted as a drop rather than vanishing.
asio::awaitable<void> cancel_drains_queued_items(asio::io_context &ctx) {
  blocking_queue<int> q(ctx, 1024, 16);

  for (int i = 0; i < 10; ++i) {
    q.push(i);
  }
  CHECK_EQ(q.size(), static_cast<std::size_t>(10));
  CHECK_EQ(q.drops(), static_cast<std::size_t>(0));

  q.cancel();

  // Nothing is left behind in a queue nobody is going to read again...
  CHECK_EQ(q.size(), static_cast<std::size_t>(0));
  // ... and the ten items were accounted for, not lost.
  CHECK_EQ(q.drops(), static_cast<std::size_t>(10));

  // The session is still usable afterwards: the drain cancelled the pending
  // sends, not the channel, and the tokens the drained items owned are skipped
  // rather than read as items (that skip is the old front()-on-empty UB).
  q.push(4242);
  CHECK_EQ(co_await q.pop(), 4242);
  CHECK_EQ(q.size(), static_cast<std::size_t>(0));
  CHECK_EQ(q.drops(), static_cast<std::size_t>(10));
}

// (7) The reviewer's accounting case: four threads pushing 10 000 items each
// into one bounded queue, a consumer that can only spare ten, then a cancel().
// Three things are pinned at once: the size is bounded at EVERY moment (not
// merely once it settles), no pop() ever reads past an empty queue, and
// pushed == delivered + dropped + queued holds exactly.
asio::awaitable<void> concurrent_bounded_accounting(asio::io_context &ctx) {
  constexpr int producer_count = 4;
  constexpr int per_producer = 10000;
  constexpr std::size_t cap = 64;
  constexpr int pop_count = 10;

  blocking_queue<int> q(ctx, 1024, cap);

  std::atomic<std::size_t> max_seen{0};
  std::atomic<bool> sampling{true};
  std::thread sampler([&] {
    while (sampling.load()) {
      const auto n = q.size();
      auto prev = max_seen.load();
      while (n > prev && !max_seen.compare_exchange_weak(prev, n)) {
      }
    }
  });

  // Four producers on their own threads, and deliberately no consumer on the
  // io thread while they run: the join parks it exactly the way give_up()
  // parks the real injectee, so the queue takes the whole storm.
  std::vector<std::thread> pushers;
  for (int p = 0; p < producer_count; ++p) {
    pushers.emplace_back([&q, p] {
      for (int i = 0; i < per_producer; ++i) {
        q.push(p * per_producer + i);
      }
    });
  }
  for (auto &t : pushers) {
    t.join();
  }
  sampling.store(false);
  sampler.join();

  CHECK_EQ(q.size(), cap);
  CHECK(max_seen.load() <= cap);

  // The consumer that cannot keep up: ten items, then it stops.  Cancelled
  // here would be a bug, so a throw is recorded rather than swallowed.
  std::vector<int> got;
  bool pop_threw = false;
  asio::co_spawn(
      ctx, [&]() -> asio::awaitable<void> {
        try {
          for (int i = 0; i < pop_count; ++i) {
            got.push_back(co_await q.pop());
          }
        } catch (const asio::system_error &) {
          pop_threw = true;
        }
      },
      asio::detached);

  for (int spin = 0; spin < 1000 && static_cast<int>(got.size()) < pop_count;
       ++spin) {
    co_await asio::post(ctx, asio::use_awaitable);
  }

  CHECK(!pop_threw);
  CHECK_EQ(got.size(), static_cast<std::size_t>(pop_count));
  // No underflow: every value handed back is one that was pushed, and exactly
  // once -- forty thousand distinct ints went in, so a repeat or a stray is a
  // read past the end of the deque.
  std::sort(got.begin(), got.end());
  CHECK(std::adjacent_find(got.begin(), got.end()) == got.end());
  CHECK(!got.empty());
  CHECK(got.front() >= 0);
  CHECK(got.back() < producer_count * per_producer);

  q.cancel();
  CHECK_EQ(q.size(), static_cast<std::size_t>(0));

  const auto pushed = static_cast<std::size_t>(producer_count) *
                      static_cast<std::size_t>(per_producer);
  CHECK_EQ(got.size() + q.drops() + q.size(), pushed);
}

// (8) The bound has to bind by DROPPING, never by blocking: push() runs on a
// hooked winsock call inside somebody else's process, so the only acceptable
// price of a full queue is a lost report.  Burst shape is the worst case for a
// push that tries to wait -- max (4) sits far below capacity (16) so the token
// channel is full with no receiver long before the item bound is reached, and
// nothing services `ctx` while the loop runs, because this body owns the only
// io thread.  That is the wedged-UI/injector M5 was about.
//
// Eviction DIRECTION is pinned by value too, since queue.hpp chose
// `_qu.pop()` (drop the oldest, keep the newest report) rather than refusing
// the newcomer; the two are only told apart by looking at what survives.
asio::awaitable<void> bounded_push_drops_instead_of_blocking(
    asio::io_context &ctx) {
  constexpr std::size_t cap = 16;
  constexpr int burst = 4000;
  constexpr long long budget_ms = 100;

  // Warm up on a throwaway queue first, so the measured loop is the loop under
  // test and not the process's first touch of the deque/coroutine allocations.
  {
    blocking_queue<int> warm(ctx, 4, cap);
    for (int i = 0; i < 256; ++i) {
      warm.push(i);
    }
  }

  blocking_queue<int> q(ctx, 4, cap);
  CHECK_EQ(q.capacity(), cap);
  CHECK_EQ(q.drops(), static_cast<std::size_t>(0));

  const auto begin = std::chrono::steady_clock::now();
  for (int i = 0; i < burst; ++i) {
    q.push(i);
  }
  const auto end = std::chrono::steady_clock::now();
  const long long elapsed_ms = std::chrono::duration_cast<
      std::chrono::milliseconds>(end - begin).count();

  std::printf("  note: %d pushes into a capacity-%d queue took %lldms\n",
              burst, static_cast<int>(cap), elapsed_ms);
  std::printf("  note: budget for that loop was %lldms\n", budget_ms);
  CHECK(elapsed_ms < budget_ms);

  // The producer never waited, and the bound held: the first cap items got in
  // and every one after them evicted exactly one, so the queue is at capacity.
  CHECK_EQ(q.size(), cap);
  CHECK_EQ(q.drops(), static_cast<std::size_t>(burst) - cap);

  // What survives is the NEWEST window, 3984..3999 in order.  Sixteen tokens
  // were ever posted (an eviction takes the dropped item's token with it), so
  // exactly sixteen pops are satisfiable -- no phantom, no stranded send.
  for (int i = burst - static_cast<int>(cap); i < burst; ++i) {
    CHECK_EQ(co_await q.pop(), i);
  }
  CHECK_EQ(q.size(), static_cast<std::size_t>(0));
  CHECK_EQ(q.drops(), static_cast<std::size_t>(burst) - cap);

  {
    // capacity 1 is the smallest honest window and the case that separates the
    // two eviction directions outright: oldest-drop keeps the LAST value that
    // came in, newest-drop (refusing the newcomer) would have kept the first.
    blocking_queue<int> one(ctx, 4, 1);
    one.push(11);
    one.push(22);
    one.push(33);
    CHECK_EQ(one.size(), static_cast<std::size_t>(1));
    CHECK_EQ(one.drops(), static_cast<std::size_t>(2));
    CHECK_EQ(co_await one.pop(), 33);
    CHECK_EQ(one.size(), static_cast<std::size_t>(0));
  }
}

// (9) Drop accounting across more than one burst: drops() is a lifetime
// counter, not a per-burst one.  Nothing pops between the two bursts, so the
// second one evicts on every single push and the counter only climbs.
asio::awaitable<void> drop_counter_accumulates_across_bursts(
    asio::io_context &ctx) {
  constexpr std::size_t cap = 32;
  constexpr int burst_a = 100;
  constexpr int burst_b = 50;

  blocking_queue<int> q(ctx, 1024, cap);
  CHECK_EQ(q.drops(), static_cast<std::size_t>(0));

  for (int i = 0; i < burst_a; ++i) {
    q.push(i);
  }
  const auto drops_a = q.drops();
  CHECK_EQ(drops_a, static_cast<std::size_t>(burst_a) - cap);
  CHECK_EQ(q.size(), cap);

  for (int i = 0; i < burst_b; ++i) {
    q.push(burst_a + i);
  }
  // Added to, not reset and not clamped at the first burst's overflow...
  CHECK_EQ(q.drops(), drops_a + static_cast<std::size_t>(burst_b));
  // ... so the honest closed form after an undrained producer is exactly
  // (produced - capacity), and the queue still holds precisely one window.
  CHECK_EQ(q.drops(), static_cast<std::size_t>(burst_a + burst_b) - cap);
  CHECK_EQ(q.size(), cap);

  std::vector<int> survivors;
  survivors.reserve(cap);
  for (std::size_t i = 0; i < cap; ++i) {
    survivors.push_back(co_await q.pop());
  }
  CHECK_EQ(survivors.front(), burst_a + burst_b - static_cast<int>(cap));
  CHECK_EQ(survivors.back(), burst_a + burst_b - 1);
  // pushed == delivered + dropped + queued, with the counter unchanged by the
  // draining pops themselves (popping is not a drop).
  CHECK_EQ(static_cast<std::size_t>(burst_a + burst_b),
           survivors.size() + q.drops() + q.size());

  // Emptying the window does not reset the counter either: a push that fits
  // adds nothing to it.
  const auto drops_after = q.drops();
  q.push(999);
  CHECK_EQ(q.drops(), drops_after);
  CHECK_EQ(co_await q.pop(), 999);
  CHECK_EQ(q.drops(), drops_after);
}

// (10) The bound is a sliding window, not a lifetime budget: once K items have
// been popped, K more fit again without a single eviction.  If capacity were
// implemented as "count pushes and start refusing", the pops below would free
// nothing and the second phase would report drops.
asio::awaitable<void> capacity_is_a_sliding_window(asio::io_context &ctx) {
  constexpr std::size_t cap = 8;

  blocking_queue<int> q(ctx, 1024, cap);

  for (int i = 0; i < static_cast<int>(cap); ++i) {
    q.push(i);
  }
  CHECK_EQ(q.size(), cap);
  CHECK_EQ(q.drops(), static_cast<std::size_t>(0)); // exactly full is not over

  q.push(8); // one over the line: admitted, and the OLDEST pays for it
  CHECK_EQ(q.size(), cap);
  CHECK_EQ(q.drops(), static_cast<std::size_t>(1));

  for (int i = 1; i <= 4; ++i) { // the consumer gets 1,2,3,4
    CHECK_EQ(co_await q.pop(), i);
  }
  CHECK_EQ(q.size(), static_cast<std::size_t>(4));

  const auto drops_before = q.drops();
  for (int i = 9; i <= 12; ++i) { // room for four again
    q.push(i);
  }
  CHECK_EQ(q.size(), cap);
  CHECK_EQ(q.drops(), drops_before); // zero evictions: the window slid

  q.push(13); // full again -> the next oldest (5) is the one that goes
  CHECK_EQ(q.drops(), drops_before + 1);
  for (int i = 6; i <= 13; ++i) {
    CHECK_EQ(co_await q.pop(), i);
  }
  CHECK_EQ(q.size(), static_cast<std::size_t>(0));
}

// (11) cancel() drains the queue and counts what it removed (scenario 6), but
// the tokens those items owned survive -- asio offers no way to flush a
// buffered channel -- so the next pop() has to chew through stale tokens
// before it parks again.  The promise under test is the one a reconnecting
// session lives on: a waiter parked AFTER the cancel is still woken by a later
// push, and the stale-token skip neither throws nor delivers a phantom.
asio::awaitable<void> push_after_cancel_wakes_a_later_waiter(
    asio::io_context &ctx) {
  constexpr int stranded = 5;

  blocking_queue<int> q(ctx, 1024, 16);
  for (int i = 0; i < stranded; ++i) {
    q.push(i);
  }
  q.cancel();
  CHECK_EQ(q.size(), static_cast<std::size_t>(0));
  CHECK_EQ(q.drops(), static_cast<std::size_t>(stranded));

  bool woke = false;
  bool threw = false;
  int value = 0;
  asio::co_spawn(
      ctx,
      [&]() -> asio::awaitable<void> {
        try {
          value = co_await q.pop();
          woke = true;
        } catch (const asio::system_error &) {
          threw = true;
        }
      },
      asio::detached);

  // Plenty of turns to eat the five stale tokens and park; it must not come
  // back with anything, because nothing is queued any more.
  for (int i = 0; i < 32; ++i) {
    co_await asio::post(ctx, asio::use_awaitable);
  }
  CHECK(!threw);
  CHECK(!woke);

  q.push(4321); // the first push after the drain must still reach a waiter
  for (int spin = 0; spin < 64 && !woke && !threw; ++spin) {
    co_await asio::post(ctx, asio::use_awaitable);
  }
  CHECK(!threw);
  CHECK(woke); // a lost wakeup here is the deadlock, bounded by the watchdog
  CHECK_EQ(value, 4321);
  CHECK_EQ(q.size(), static_cast<std::size_t>(0));
  // Skipping stale tokens adds no drops: 6 pushed == 1 delivered + 5 drained.
  CHECK_EQ(q.drops(), static_cast<std::size_t>(stranded));
  CHECK_EQ(static_cast<std::size_t>(1) + q.drops() + q.size(),
           static_cast<std::size_t>(stranded + 1));

  // cancel() on a queue that holds nothing is idempotent, not a second
  // accounting event.
  q.cancel();
  CHECK_EQ(q.drops(), static_cast<std::size_t>(stranded));
  CHECK_EQ(q.size(), static_cast<std::size_t>(0));
}

// (12) Regression guard for the OTHER caller: the injector side still builds
// its queue with the defaulted capacity, and there the item side must keep
// growing however hard it is fed.  `unbounded` is 0, which in this API means
// "no bound" and emphatically not "a bound of zero" -- the trap if the check
// in push() were ever written as `_qu.size() >= _capacity` unconditionally.
asio::awaitable<void> default_capacity_stays_unbounded(
    asio::io_context &ctx) {
  constexpr int burst = 512; // far above every capacity used above

  CHECK_EQ(blocking_queue<int>::unbounded, static_cast<std::size_t>(0));

  {
    blocking_queue<int> q(ctx, 8); // the pre-bc428c9 two-argument call
    CHECK_EQ(q.capacity(), blocking_queue<int>::unbounded);
    for (int i = 0; i < burst; ++i) {
      q.push(i);
    }
    CHECK_EQ(q.size(), static_cast<std::size_t>(burst));
    CHECK_EQ(q.drops(), static_cast<std::size_t>(0));
    for (int i = 0; i < burst; ++i) {
      CHECK_EQ(co_await q.pop(), i);
    }
    CHECK_EQ(q.size(), static_cast<std::size_t>(0));
    CHECK_EQ(q.drops(), static_cast<std::size_t>(0));
  }

  {
    // An explicit unbounded is the same thing as the default, not a clamp.
    blocking_queue<int> q(ctx, 8, blocking_queue<int>::unbounded);
    CHECK_EQ(q.capacity(), static_cast<std::size_t>(0));
    for (int i = 0; i < 2 * burst; ++i) {
      q.push(i);
    }
    CHECK_EQ(q.size(), static_cast<std::size_t>(2 * burst));
    CHECK_EQ(q.drops(), static_cast<std::size_t>(0));
    CHECK_EQ(co_await q.pop(), 0);
  }
}

void test_fifo_order() {
  run_scenario("fifo_order", fifo_order);
}

void test_single_consumer_drains() {
  run_scenario("single_consumer_drains", single_consumer_drains);
}

void test_cancel_wakes_pending_pop() {
  run_scenario("cancel_wakes_pending_pop", cancel_wakes_pending_pop);
}

void test_destructor_with_pending_items() {
  run_scenario("destructor_with_pending_items", destructor_with_pending_items);
}

void test_overflow_drops_oldest_and_counts() {
  run_scenario("overflow_drops_oldest_and_counts",
               overflow_drops_oldest_and_counts);
}

void test_cancel_drains_queued_items() {
  run_scenario("cancel_drains_queued_items", cancel_drains_queued_items);
}

void test_concurrent_bounded_accounting() {
  run_scenario("concurrent_bounded_accounting", concurrent_bounded_accounting);
}

void test_bounded_push_drops_instead_of_blocking() {
  run_scenario("bounded_push_drops_instead_of_blocking",
               bounded_push_drops_instead_of_blocking);
}

void test_drop_counter_accumulates_across_bursts() {
  run_scenario("drop_counter_accumulates_across_bursts",
               drop_counter_accumulates_across_bursts);
}

void test_capacity_is_a_sliding_window() {
  run_scenario("capacity_is_a_sliding_window", capacity_is_a_sliding_window);
}

void test_push_after_cancel_wakes_a_later_waiter() {
  run_scenario("push_after_cancel_wakes_a_later_waiter",
               push_after_cancel_wakes_a_later_waiter);
}

void test_default_capacity_stays_unbounded() {
  run_scenario("default_capacity_stays_unbounded",
               default_capacity_stays_unbounded);
}

} // namespace

int main() {
  RUN(test_fifo_order);
  RUN(test_single_consumer_drains);
  RUN(test_cancel_wakes_pending_pop);
  RUN(test_destructor_with_pending_items);
  RUN(test_overflow_drops_oldest_and_counts);
  RUN(test_cancel_drains_queued_items);
  RUN(test_concurrent_bounded_accounting);
  RUN(test_bounded_push_drops_instead_of_blocking);
  RUN(test_drop_counter_accumulates_across_bursts);
  RUN(test_capacity_is_a_sliding_window);
  RUN(test_push_after_cancel_wakes_a_later_waiter);
  RUN(test_default_capacity_stays_unbounded);

  // Keep the ctest TIMEOUT honest: it is sized as kScenarioCount x
  // kWatchdogMs + margin.  A 13th RUN() line that leaves both numbers alone is
  // how a named scenario FAIL silently goes back to being an anonymous
  // timeout, so the coupling is checked here rather than trusted to a comment.
  if (scenarios_run != kScenarioCount) {
    ++test_failures;
    std::printf("FAIL ran %d scenarios but kScenarioCount is %d; the TIMEOUT"
                " in tests/queue/CMakeLists.txt must move with it"
                "  (%d x %dms + margin)\n",
                scenarios_run, kScenarioCount, kScenarioCount, kWatchdogMs);
  }
  // An abandoned io thread is parked inside a call the test has already
  // reported as hung, and it is still holding whatever that call had locked --
  // a mutex, an asio channel, a std::thread it is joining.  The scenario
  // verdicts above are complete and printed, but an orderly return from main
  // can then wait on those locks forever, which would put us straight back
  // where we started: a ctest TIMEOUT with the names buried in the log.  So
  // flush and leave by the door that cannot block, and let the exit code be
  // the failure count.
  if (scenarios_abandoned) {
    std::fflush(stdout);
    std::_Exit(static_cast<unsigned>(test_failures));
  }
  return test_failures;
}
