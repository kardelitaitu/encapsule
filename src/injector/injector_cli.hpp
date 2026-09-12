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

#ifndef ENCAPSULE_INJECTOR_INJECTOR_CLI
#define ENCAPSULE_INJECTOR_INJECTOR_CLI

#include "server.hpp"
#include <spdlog/fmt/ostr.h>
#include <spdlog/spdlog.h>
#include <sstream>

using spdlog::info;

// Every field of a report message is optional on the wire: protopuf keeps an
// absent one as std::nullopt, and "absent" is a different answer from
// "empty" (the P5 contract, pinned by tests/schema).  So a field is looked
// at before it is used, and these two fixed strings are what comes out
// instead -- on this side of the socket the sender is a process the tool has
// no authority over, and a truncated report is a line to print, not a
// dereference of an empty optional on the thread that keeps the tool alive.
constexpr const char *unset_field = "<unset>";
constexpr const char *dropped_report = "a connection report was not printed";

struct injectee_session_cli : injectee_session {
  using injectee_session::injectee_session;

  asio::awaitable<void> process_connect(const InjecteeConnect &msg) override {
    // Every report is printed from a coroutine running detached on the io
    // thread, so a throw here -- the formatting, the buffering, or a field
    // nobody checked -- ends the tool with live capsules still routed.  The
    // line is assembled first and printed from one string, which keeps the
    // output byte-for-byte what the two-branch version wrote while letting a
    // single check cover every field.
    try {
      std::ostringstream line;
      line << (int)pid_ << ": ";
      if (const auto &syscall = msg["syscall"_f])
        line << *syscall;
      else
        line << unset_field;

      line << " ";
      if (const auto &addr = msg["addr"_f])
        line << *addr;
      else
        line << unset_field;

      if (const auto &proxy = msg["proxy"_f])
        info("{} via {}", line.str(), *proxy);
      else
        info("{}", line.str());
    } catch (...) {
      info(dropped_report);
    }

    co_return;
  }

  asio::awaitable<void> process_pid() override {
    try {
      info("{}: established injectee connection", (int)pid_);
    } catch (...) {
      info(dropped_report);
    }

    co_return;
  }

  void process_close() override {
    try {
      info("{}: closed", (int)pid_);
    } catch (...) {
      info(dropped_report);
    }

    // The bookkeeping is not optional and gets no exception of its own: the
    // count is a member read that cannot fail, and whether or not the line
    // above was printable, the session is gone and the last one still has to
    // bring the tool down.
    if (server_.clients.size() == 0) {
      try {
        info("all processes have been exited, exit");
      } catch (...) {
      }

      exit(0);
    }
  }
};

// The endpoint string itself is parsed in <utils.hpp> (parse_proxy_url), which
// both frontends share and which understands [user[:pass]@] and bracketed
// IPv6 hosts.  It replaces the find_last_of(':') helper that used to live
// here: that one turned "[2001:db8::1]:1080" into the host "[2001:db8::1]" --
// brackets included, so un-parseable -- and threw on a non-numeric port.

#endif
