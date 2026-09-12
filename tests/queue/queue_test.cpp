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
#include <cstdio>
#include <exception>
#include <thread>
#include <vector>

// blocking_queue<T> is a std::queue guarded by a channel<void(error_code)>.
// Every scenario below runs on its own io_context, started with asio::co_spawn
// and bounded by a steady_timer watchdog, so a stuck channel fails the test
// instead of hanging CI.  The per-scenario budget keeps the worst case
// (7 scenarios) below the 60s TIMEOUT set on common.queue in CMake.
namespace {

constexpr int kWatchdogMs = 8000;
constexpr int kItems = 64;
constexpr int kSentinel = -7;

struct scenario {
  asio::io_context ctx;
  asio::steady_timer watchdog;
  bool timed_out;
  std::exception_ptr error;

  scenario() : ctx(), watchdog(ctx), timed_out(false), error() {}

  scenario(const scenario &) = delete;
  scenario &operator=(const scenario &) = delete;
};

// Runs `body` (an awaitable taking the io_context) until it finishes or the
// watchdog expires; whichever happens first stops the context.
template <typename Body>
void run_scenario(const char *name, Body body) {
  scenario s;

  s.watchdog.expires_after(std::chrono::milliseconds(kWatchdogMs));
  s.watchdog.async_wait([&s](asio::error_code ec) {
    if (!ec) {
      s.timed_out = true;
      s.ctx.stop();
    }
  });

  asio::co_spawn(s.ctx, body(s.ctx), [&s](std::exception_ptr e) {
    s.error = e;
    s.ctx.stop();
  });

  s.ctx.run();
  s.watchdog.cancel();

  CHECK(!s.timed_out);
  if (s.timed_out) {
    std::printf("  [%s] watchdog expired after %dms: channel stuck\n", name,
                kWatchdogMs);
  }

  CHECK(!s.error);
  if (s.error) {
    try {
      std::rethrow_exception(s.error);
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

} // namespace

int main() {
  RUN(test_fifo_order);
  RUN(test_single_consumer_drains);
  RUN(test_cancel_wakes_pending_pop);
  RUN(test_destructor_with_pending_items);
  RUN(test_overflow_drops_oldest_and_counts);
  RUN(test_cancel_drains_queued_items);
  RUN(test_concurrent_bounded_accounting);
  return test_failures;
}
