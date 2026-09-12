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

using spdlog::info;

struct injectee_session_cli : injectee_session {
  using injectee_session::injectee_session;

  asio::awaitable<void> process_connect(const InjecteeConnect &msg) override {
    if (auto v = msg["proxy"_f])
      info("{}: {} {} via {}", (int)pid_, *msg["syscall"_f], *msg["addr"_f],
           *v);
    else
      info("{}: {} {}", (int)pid_, *msg["syscall"_f], *msg["addr"_f]);
    co_return;
  }

  asio::awaitable<void> process_pid() override {
    info("{}: established injectee connection", (int)pid_);
    co_return;
  }

  void process_close() override {
    info("{}: closed", (int)pid_);
    if (server_.clients.size() == 0) {
      info("all processes have been exited, exit");

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
