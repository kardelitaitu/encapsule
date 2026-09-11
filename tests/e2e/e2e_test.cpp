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

// End-to-end smoke harness.
//
//   --selfcheck                loopback only: relay + decoy, no injection.
//                              Runs anywhere, no admin, no proxy.
//   --cli X --dummy Y         the real inject-and-connect test (E1); not
//                              implemented yet, so it exits 77 (CTest skip).
//
// The self-check is the contract the injection test will reuse: a decoy process
// that cannot reach its target goes through the socks5 relay, and the harness
// asserts on what the relay actually saw on the wire.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>

#include "test_support.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include "socks5_test_server.hpp"

#ifndef PROXINJECT_E2E_DUMMY_NAME
#define PROXINJECT_E2E_DUMMY_NAME "proxinject_e2e_dummy.exe"
#endif

namespace {

using clock_type = std::chrono::steady_clock;

constexpr int kRecordDeadlineMs = 60000; // how long to wait for a CONNECT
constexpr int kAcceptDeadlineMs = 30000; // how long to wait for the decoy
constexpr int kRejectDeadlineMs = 4000;  // ditto, for the refusal scenario
constexpr int kIntervalMs = 300;     // decoy retry cadence, per the contract
constexpr int kExitNoRoundTrip = 3;  // dummy_target's "no round trip" code

std::string g_dummy_override; // from --dummy, so CMake owns the real path

// ---------------------------------------------------------------- process --

// Spawns a child and guarantees it is gone when the scope exits.
class child_process {
public:
  child_process() = default;
  child_process(const child_process &) = delete;
  child_process &operator=(const child_process &) = delete;
  ~child_process() {
    stop();
  }

  bool spawn(const std::string &command_line) {
    std::vector<char> mutable_line(command_line.begin(), command_line.end());
    mutable_line.push_back('\0');
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    pi_ = {};
    const BOOL ok = CreateProcessA(
        nullptr, mutable_line.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, nullptr, &si, &pi_);
    if (!ok) {
      std::printf("  FAIL cannot spawn: err=%lu\n    %s\n", GetLastError(),
                  command_line.c_str());
      return false;
    }
    started_ = true;
    return true;
  }

  bool running() const {
    return started_ && WaitForSingleObject(pi_.hProcess, 0) == WAIT_TIMEOUT;
  }

  bool wait(std::chrono::milliseconds timeout) const {
    if (!started_) {
      return false;
    }
    return WaitForSingleObject(pi_.hProcess,
                               static_cast<DWORD>(timeout.count())) ==
           WAIT_OBJECT_0;
  }

  unsigned long exit_code() const {
    unsigned long code = 0xFFFFFFFF;
    if (started_) {
      GetExitCodeProcess(pi_.hProcess, &code);
    }
    return code;
  }

  void stop() {
    if (!started_) {
      return;
    }
    if (running()) {
      TerminateProcess(pi_.hProcess, 0xBED);
      wait(std::chrono::milliseconds(5000));
    }
    CloseHandle(pi_.hThread);
    CloseHandle(pi_.hProcess);
    started_ = false;
  }

private:
  PROCESS_INFORMATION pi_ = {};
  bool started_ = false;
};

std::string quoted(const std::string &text) {
  return "\"" + text + "\"";
}

std::string exe_dir() {
  char path[MAX_PATH] = {};
  const DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) {
    return {};
  }
  const std::string full(path, n);
  const std::size_t sep = full.find_last_of("\\/");
  return sep == std::string::npos ? std::string() : full.substr(0, sep + 1);
}

std::string dummy_path() {
  if (!g_dummy_override.empty()) {
    return g_dummy_override;
  }
  // The dummy lands next to this exe: both use test_bin/<config>/.
  return exe_dir() + PROXINJECT_E2E_DUMMY_NAME;
}

std::string dummy_command(const std::string &exe, const std::string &host,
                          std::uint16_t port, int deadline_ms,
                          const std::string &sentinel, bool socks5) {
  std::string cmd = quoted(exe) + " --host " + host + " --port " +
                     std::to_string(port) + " --interval-ms " +
                     std::to_string(kIntervalMs) + " --deadline-ms " +
                     std::to_string(deadline_ms) + " --sentinel " +
                     quoted(sentinel);
  if (socks5) {
    cmd += " --socks5";
  }
  return cmd;
}

// -------------------------------------------------------------- scenarios --

// The relay must see a well-formed CONNECT for the address the decoy dialed,
// and the sentinel must come back through it.
void relay_records_connect_and_echoes() {
  e2e::socks5_test_server server;
  CHECK(server.port() != 0);
  std::printf("  relay on %s:%u\n", server.address().c_str(),
            static_cast<unsigned>(server.port()));

  const std::string sentinel = "E2E-SENTINEL-ACCEPT";
  child_process child;
  const bool spawned = child.spawn(
      dummy_command(dummy_path(), server.address(), server.port(),
                    kAcceptDeadlineMs, sentinel, true));
  CHECK(spawned);
  if (!spawned) {
    return;
  }

  CHECK(server.wait_for_request_count(1, std::chrono::milliseconds(
                                             kRecordDeadlineMs)));
  const auto records = server.requests();
  CHECK(!records.empty());
  if (!records.empty()) {
    const auto &rec = records.front();
    CHECK_EQ(static_cast<int>(rec.atyp), static_cast<int>(SOCKS_IPV4));
    CHECK_EQ(rec.addr, std::string("127.0.0.1"));
    CHECK_EQ(static_cast<int>(rec.port), static_cast<int>(server.port()));
    std::printf("  CONNECT %s(%s):%u\n", e2e::atyp_name(rec.atyp).c_str(),
                rec.addr.c_str(), static_cast<unsigned>(rec.port));
  }

  // exit 0 from the decoy is the proof the sentinel survived the echo loop
  CHECK(child.wait(std::chrono::milliseconds(kAcceptDeadlineMs)));
  CHECK_EQ(static_cast<int>(child.exit_code()), 0);
  CHECK(server.echoed_round_trips() >= 1);
  std::printf("  echoed %zu byte(s) in %zu chunk(s)\n", server.echoed_bytes(),
              server.echoed_round_trips());
}

// The on_connect hook must be able to veto a CONNECT, and the decoy must be
// unable to complete a round trip while it does.
void on_connect_hook_can_refuse() {
  // Declared before the server: ~socks5_test_server joins the worker, and the
  // hook it may still call captures these by reference.
  std::atomic<std::size_t> hook_calls{0};
  std::atomic<bool> saw_ipv4{false};

  e2e::socks5_test_server server;
  server.set_on_connect([&](const e2e::socks5_test_server::request &rec) {
    ++hook_calls;
    saw_ipv4.store(rec.atyp == SOCKS_IPV4);
    return static_cast<char>(SOCKS_GENERAL_FAILURE);
  });

  const std::string sentinel = "E2E-SENTINEL-REFUSED";
  child_process child;
  const bool spawned = child.spawn(dummy_command(
      dummy_path(), server.address(), server.port(), kRejectDeadlineMs,
      sentinel, true));
  CHECK(spawned);
  if (!spawned) {
    return;
  }

  CHECK(child.wait(std::chrono::milliseconds(kRecordDeadlineMs)));
  CHECK_EQ(static_cast<int>(child.exit_code()), kExitNoRoundTrip);
  CHECK(hook_calls.load() >= 1);
  CHECK(saw_ipv4.load());
  CHECK_EQ(server.echoed_round_trips(), std::size_t(0));
  std::printf("  refused %zu CONNECT(s), echoed nothing\n", hook_calls.load());
}

void run_selfcheck() {
  RUN(relay_records_connect_and_echoes);
  RUN(on_connect_hook_can_refuse);
}

// ------------------------------------------------------------------ inject --

// Placeholder for E1: start the relay, launch the decoy against a dead
// address, inject proxinjectee.dll into it with proxinjector-cli pointed at
// this relay, then assert the relay saw the CONNECT the injectee built.
int run_inject(const std::string &cli, const std::string &dummy) {
  if (cli.empty() || dummy.empty()) {
    std::printf("usage: e2e_test --inject --cli <proxinjector-cli> "
                "--dummy <dummy_target>\n");
    return 2;
  }
  std::printf("SKIP e2e.inject_connect: the injection driver is not "
              "implemented yet (cli=%s dummy=%s)\n",
              cli.c_str(), dummy.c_str());
  return 77; // CTest skip code
}

} // namespace

int main(int argc, char **argv) {
  std::vector<std::string> args;
  args.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
  for (int i = 1; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }

  std::string mode;
  std::string cli;
  for (std::size_t i = 0; i < args.size(); ++i) {
    const std::string &flag = args[i];
    auto take = [&](std::string &slot) {
      if (i + 1 >= args.size()) {
        return false;
      }
      slot = args[++i];
      return true;
    };
    if (flag == "--selfcheck") {
      mode = "selfcheck";
    } else if (flag == "--inject") {
      mode = "inject";
    } else if (flag == "--cli") {
      if (!take(cli)) {
        std::printf("--cli needs a value\n");
        return 2;
      }
    } else if (flag == "--dummy") {
      if (!take(g_dummy_override)) {
        std::printf("--dummy needs a value\n");
        return 2;
      }
    } else {
      std::printf("unknown argument %s\n", flag.c_str());
      std::printf("usage: e2e_test --selfcheck | --inject --cli X --dummy Y\n");
      return 2;
    }
  }

  // CMake registers the injection test as '--cli X --dummy Y' with no mode
  // flag, so a target path on its own means injection mode.
  if (mode.empty() && (!cli.empty() || !g_dummy_override.empty())) {
    mode = "inject";
  }

  WSADATA wsa = {};
  WSAStartup(MAKEWORD(2, 2), &wsa);

  int result = 0;
  if (mode == "selfcheck") {
    run_selfcheck();
    result = test_failures;
  } else if (mode == "inject") {
    result = run_inject(cli, g_dummy_override);
  } else {
    std::printf("usage: e2e_test --selfcheck | --inject --cli X --dummy Y\n");
    result = 2;
  }

  WSACleanup();
  return result;
}
