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

#include "injector.hpp"
#include "injector_cli.hpp"
#include "utils.hpp"
#include "version.hpp"
#include <argparse/argparse.hpp>
#include <iostream>

using argparse::ArgumentParser;
using namespace std;

auto create_parser() {
  ArgumentParser parser("encapsule-cli", encapsule_version,
                        argparse::default_arguments::help);

  parser.add_description(encapsule_description);

  parser.add_argument("-v", "--version")
      .action([&](const auto & /*unused*/) {
        std::cout << encapsule_copyright(encapsule_version) << std::endl;
        std::exit(0);
      })
      .default_value(false)
      .help("prints version information and exits")
      .implicit_value(true)
      .nargs(0);

  parser.add_argument("-i", "--pid")
      .help("pid of a process to inject proxy (integer)")
      .default_value(vector<int>{})
      .scan<'d', int>()
      .append();

  parser.add_argument("-n", "--name")
      .help("short filename of a process with wildcard matching to inject "
            "proxy (string, without directory and file extension, e.g. "
            "`python`, `py*`, `py??on`)")
      .default_value(vector<string>{})
      .append();

  parser.add_argument("-P", "--path")
      .help("full filename of a process with wildcard matching to inject proxy "
            "(string, with directory and file extension, e.g. "
            "`C:/programs/python.exe`, `C:/programs/*.exe`)")
      .default_value(vector<string>{})
      .append();

  parser.add_argument("-r", "--name-regexp")
      .help("regular expression for short filename of a process "
            "to inject proxy (string, without directory and file "
            "extension, e.g. `python`, `py.*|exp.*`)")
      .default_value(vector<string>{})
      .append();

  parser.add_argument("-R", "--path-regexp")
      .help("regular expression for full filename of a process "
            "to inject proxy (string, with directory and file "
            "extension, e.g. `C:/programs/python.exe`, "
            "`C:/programs/(a|b).*\\.exe`)")
      .default_value(vector<string>{})
      .append();

  parser.add_argument("-e", "--exec")
      .help("command line started with an executable to create a new process "
            "and inject proxy (string, e.g. `python` or `C:\\Program "
            "Files\\a.exe --some-option`)")
      .default_value(vector<string>{})
      .append();

  parser.add_argument("-l", "--enable-log")
      .help("enable logging for network connections")
      .default_value(false)
      .implicit_value(true);

  parser.add_argument("-p", "--set-proxy")
      .help("set a proxy address for network connections (string, "
            "`[user[:pass]@]host:port`, e.g. `127.0.0.1:1080`, "
            "`[2001:db8::1]:1080` or `user:pass@127.0.0.1:1080`)")
      .default_value(string{});

  parser.add_argument("-w", "--new-console-window")
      .help("create a new console window while a new console process is "
            "executed in `-e`")
      .default_value(false)
      .implicit_value(true);

  parser.add_argument("-s", "--subprocess")
      .help("inject subprocesses created by these already injected processes")
      .default_value(false)
      .implicit_value(true);

  return parser;
}

int main(int argc, char *argv[]) {
  auto parser = create_parser();

  try {
    parser.parse_args(argc, argv);
  } catch (const runtime_error &err) {
    cerr << err.what() << endl;
    cerr << parser;
    return 1;
  }

  auto pids = parser.get<vector<int>>("-i");
  auto proc_names = parser.get<vector<string>>("-n");
  auto proc_paths = parser.get<vector<string>>("-P");
  auto proc_re_names = parser.get<vector<string>>("-r");
  auto proc_re_paths = parser.get<vector<string>>("-R");
  auto create_paths = parser.get<vector<string>>("-e");

  if (pids.empty() && proc_names.empty() && create_paths.empty()) {
    cerr << "Expected at least one of `-i`, `-n` or `-e`" << endl;
    cerr << parser;
    return 2;
  }

  // The proxy endpoint is parsed here, before anything is started, for two
  // reasons.  A malformed `-p` has to be a hard error rather than a silently
  // unproxied run, and that exit can only be taken while there is no io thread
  // to wait for: returning once `io_thread` runs would block in its destructor
  // on an accept loop that never ends.
  std::optional<proxy_endpoint> proxy;
  std::optional<ip::address> proxy_addr;
  if (auto proxy_str = trim_copy(parser.get<string>("-p"));
      !proxy_str.empty()) {
    auto fail = [&](const string &why) {
      cerr << "Invalid proxy address `" + proxy_str + "`: " + why << endl;
      cerr << parser;
      return 2;
    };

    auto endpoint = parse_proxy_url(proxy_str);
    if (!endpoint) {
      return fail("expected [user[:pass]@]host:port");
    }

    // IpAddr carries a numeric address and never a name, so a hostname is
    // refused here instead of throwing out of the conversion below.
    asio::error_code ec;
    auto addr = ip::make_address(endpoint->host, ec);
    if (ec) {
      return fail("`" + endpoint->host +
                  "` is not a numeric IPv4 or IPv6 address");
    }

    proxy = std::move(endpoint);
    proxy_addr = addr;
  }

  asio::io_context io_context(1);
  injector_server server;

  auto acceptor = tcp::acceptor(io_context, auto_endpoint);
  server.set_port(acceptor.local_endpoint().port());
  info("connection port is set to {}", server.port_);

  asio::co_spawn(io_context,
                 listener<injectee_session_cli>(std::move(acceptor), server),
                 asio::detached);

  jthread io_thread([&io_context] { io_context.run(); });

  if (parser.get<bool>("-l")) {
    server.enable_log();
    info("logging enabled");
  }

  if (parser.get<bool>("-s")) {
    server.enable_subprocess();
    info("subprocess injection enabled");
  }

  if (proxy) {
    server.set_proxy(*proxy_addr, proxy->port);
    info("proxy address set to {}:{}", proxy->host, proxy->port);

    // Address and credentials are two lines on purpose: the second one is the
    // only place a credential is ever mentioned, and it names the user and the
    // length of the secret instead of the secret, which a log would otherwise
    // copy forever.  The parsed values go to the server exactly as they were
    // parsed: a field the user left out stays unset rather than becoming an
    // empty string, because on the wire those two mean different things.
    if (proxy->username) {
      info("credentials set (user: {}, password: {} chars)", *proxy->username,
           proxy->password ? proxy->password->size() : std::size_t(0));
      server.set_proxy_credentials(std::move(proxy->username),
                                   std::move(proxy->password));
    }
  }

  bool has_process = false;
  auto report_injected = [&has_process](DWORD pid) {
    info("{}: injected", pid);
    has_process = true;
  };

  for (auto pid : pids) {
    if (pid > 0) {
      if (server.inject(pid)) {
        report_injected(pid);
      }
    }
  }

  for (const auto &name : proc_names) {
    injector::pid_by_name_wildcard(name,
                                   [&server, &report_injected](DWORD pid) {
                                     if (server.inject(pid)) {
                                       report_injected(pid);
                                     }
                                   });
  }

  for (const auto &path : proc_paths) {
    injector::pid_by_path_wildcard(path,
                                   [&server, &report_injected](DWORD pid) {
                                     if (server.inject(pid)) {
                                       report_injected(pid);
                                     }
                                   });
  }

  for (const auto &name : proc_re_names) {
    injector::pid_by_name_regex(name, [&server, &report_injected](DWORD pid) {
      if (server.inject(pid)) {
        report_injected(pid);
      }
    });
  }

  for (const auto &path : proc_re_paths) {
    injector::pid_by_path_regex(path, [&server, &report_injected](DWORD pid) {
      if (server.inject(pid)) {
        report_injected(pid);
      }
    });
  }

  for (const auto &file : create_paths) {
    DWORD creation_flags = parser.get<bool>("-w") ? CREATE_NEW_CONSOLE : 0;
    if (auto res = create_process(file, creation_flags)) {
      if (server.inject(res->dwProcessId)) {
        report_injected(res->dwProcessId);
      }
    }
  }

  if (!has_process) {
    info("no process has been injected, exit");
    io_context.stop();
  }

  io_thread.join();
}
