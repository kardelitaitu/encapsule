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

#ifndef ENCAPSULE_COMMON_QUEUE
#define ENCAPSULE_COMMON_QUEUE

#include <asio/experimental/channel.hpp>

#include <atomic>
#include <cstddef>
#include <mutex>
#include <optional>
#include <queue>

template <typename T> using channel = asio::experimental::channel<T>;

// A std::queue guarded by a channel<void(error_code)> semaphore: push()
// appends and posts one token, pop() waits for a token and then takes the
// front item.  Two knobs, and they are not the same thing.
//
//   max      - how many tokens the channel buffers before a send has to wait
//              for a receiver; it says nothing about how much the queue holds.
//   capacity - how many items may sit in the queue.  0 (the default, and the
//              only value every existing caller passes) means unbounded, which
//              is exactly what it always was.
//
// M5: unbounded is not safe for the injectee's report queue.  That queue lives
// in a DLL that stays resident in somebody else's process for the lifetime of
// their process (client.hpp give_up(): the io_context parks on a timer that
// never expires, so no writer() coroutine is left to pop anything), while the
// winsock hooks keep pushing one report per connect (hook.hpp).  With the
// default 1024 only bounding the token, the item side grew without limit and
// each stranded item also left a pending send behind, so the victim paid for
// every connection the injector stopped listening to.  Pass a real capacity and
// that growth becomes a bounded ring that drops the OLDEST report and counts
// what it threw away - the newest report is the one the user still wants, and
// a report queue that starts refusing work at the head is what a queue that
// applies back-pressure to a hooked winsock call must do instead.
//
// Overflow drops the oldest item and, with it, the token that item owned: an
// eviction removes one and an append adds one, so the net item count is
// unchanged and no new token is posted.  That keeps "tokens ~= items" true
// rather than drifting one pending send per dropped report, which is the other
// half of the unbounded growth above.
template <typename T> class blocking_queue {
public:
  static constexpr std::size_t unbounded = 0;

  blocking_queue(asio::io_context &ctx, size_t max, size_t capacity = unbounded)
      : chan(ctx.get_executor(), max), _capacity(capacity) {}

  blocking_queue(const blocking_queue &) = delete;
  blocking_queue &operator=(const blocking_queue &) = delete;

  // The lock is held for the queue operation only; the token send is an asio
  // call and is always made after it is dropped.
  void push(const T &item) {
    bool token_needed = true;
    {
      std::lock_guard<std::mutex> lock(_sync);
      if (_capacity != unbounded && _qu.size() >= _capacity) {
        _qu.pop(); // oldest first: the newest report is the one still wanted
        _drops.fetch_add(1, std::memory_order_relaxed);
        token_needed = false;
      }
      _qu.push(item);
    }

    if (token_needed) {
      asio::co_spawn(chan.get_executor(),
                     chan.async_send(asio::error_code{}, asio::use_awaitable),
                     asio::detached);
    }
  }

  // Waits for a token, then takes the front item.  The two are only
  // approximately equal - an eviction, a cancel() drain and an in-flight pop
  // all move one side without the other - so a token with nothing behind it is
  // possible, and it is skipped rather than read.  (_qu.front() on an empty
  // queue used to be the underflow here: it is UB in release and a debug
  // iterator assert in a checked build.)
  asio::awaitable<T> pop() {
    while (true) {
      co_await chan.async_receive(asio::use_awaitable);

      std::optional<T> item;
      {
        std::lock_guard<std::mutex> lock(_sync);
        if (!_qu.empty()) {
          item.emplace(std::move(_qu.front()));
          _qu.pop();
        }
      }

      if (item) {
        co_return std::move(*item);
      }
    }
  }

  // cancel() means "this session is over, nothing will drain this again".
  // Documenting all three things it does, because the second one was the bug:
  //   - every pending async_send is aborted (asio completes it with
  //     channel_cancelled, which push() deliberately ignores);
  //   - every pop() parked on the channel wakes with channel_cancelled and
  //     rethrows, which is how injectee_client::writer() unwinds into
  //     reconnect;
  //   - everything still queued is drained here and counted as dropped.  It
  //     used to be left in _qu, and after a give_up() there is no consumer to
  //     ever come back for it: the reports were not "delayed until reconnect",
  //     they were memory held by a queue that will never be read again.
  // Tokens that were already buffered survive the cancel - asio offers no way
  // to flush them - and pop() skips them, as above.  The channel stays open,
  // so a queue that reconnects keeps working.
  void cancel() {
    chan.cancel();

    std::size_t stranded = 0;
    {
      std::lock_guard<std::mutex> lock(_sync);
      while (!_qu.empty()) {
        _qu.pop();
        ++stranded;
      }
    }
    if (stranded) {
      _drops.fetch_add(stranded, std::memory_order_relaxed);
    }
  }

  // Items currently queued, and the running total of everything that was
  // thrown away instead - by an overflow eviction or by cancel().  The two
  // plus what has been popped always equal what was pushed; the concurrency
  // test below pins that identity.
  std::size_t size() const {
    std::lock_guard<std::mutex> lock(_sync);
    return _qu.size();
  }

  std::size_t drops() const { return _drops.load(std::memory_order_relaxed); }

  std::size_t capacity() const { return _capacity; }

  ~blocking_queue() { chan.close(); }

private:
  mutable std::mutex _sync;
  std::queue<T> _qu;
  channel<void(asio::error_code)> chan;
  std::size_t _capacity;
  std::atomic<std::size_t> _drops = 0;
};

#endif
