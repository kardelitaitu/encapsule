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

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <vector>

// blocking_queue<T> is a std::queue guarded by a channel<void(error_code)>.
// Every scenario below runs on its own io_context, started with asio::co_spawn
// and bounded by a steady_timer watchdog, so a stuck channel fails the test
// instead of hanging CI.  The per-scenario budget keeps the worst case
// (4 scenarios) below the 60s TIMEOUT set on common.queue in CMake.
namespace {

constexpr int kWatchdogMs = 10000;
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
    ++test_failures;
    std::printf("  pop() returned %d instead of throwing\n", v);
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

} // namespace

int main() {
  RUN(test_fifo_order);
  RUN(test_single_consumer_drains);
  RUN(test_cancel_wakes_pending_pop);
  RUN(test_destructor_with_pending_items);
  return test_failures;
}
