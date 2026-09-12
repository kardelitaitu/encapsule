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
//   --cli X --dummy Y         inject-and-connect: the decoy hammers a dead
//                              address, encapsule-cli injects it and points
//                              it at the relay, which then asserts on the
//                              CONNECT the injectee actually built.
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
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "socks5_test_server.hpp"

// create_process(): launch the decoy the same way the product's -e does.
// winraii.hpp carries non-inline helpers, which stays safe because this is the
// only translation unit that includes it.
#include <winraii.hpp>

#ifndef ENCAPSULE_E2E_DUMMY_NAME
#define ENCAPSULE_E2E_DUMMY_NAME "encapsule_e2e_dummy.exe"
#endif

namespace {

using clock_type = std::chrono::steady_clock;

constexpr int kRecordDeadlineMs = 60000; // how long to wait for a CONNECT
constexpr int kAcceptDeadlineMs = 30000; // how long to wait for the decoy
constexpr int kRejectDeadlineMs = 4000;  // ditto, for the refusal scenario
constexpr int kIntervalMs = 300;     // decoy retry cadence, per the contract
constexpr int kExitNoRoundTrip = 3;  // dummy_target's "no round trip" code

// Injection mode.  Each bound is well inside the 60s the contract allows, so
// two scenarios still finish long before the 120s CTest TIMEOUT kills the run.
constexpr int kInjectRecordWaitMs = 25000; // wait for a CONNECT to land
constexpr int kInjectDecoyWaitMs = 25000;  // wait for the decoy to report back
constexpr int kDecoyDeadlineMs = 60000;    // the decoy's own patience

std::string g_dummy_override; // from --dummy, so CMake owns the real path
std::string g_cli_path;       // from --cli

// ---------------------------------------------------------------- process --

// Spawns or adopts a child and guarantees it is gone when the scope exits:
// TerminateProcess + CloseHandle on every path, including a CHECK failure.
class child_process {
public:
  child_process() = default;
  child_process(const child_process &) = delete;
  child_process &operator=(const child_process &) = delete;
  ~child_process() {
    finish();
  }

  // capture_output routes the child's stdout *and* stderr (spdlog writes to
  // stdout) into a pipe this side drains once the child is gone.
  bool spawn(const std::string &command_line, bool capture_output = false) {
    std::vector<char> mutable_line(command_line.begin(), command_line.end());
    mutable_line.push_back('\0');
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    HANDLE read_end = nullptr;
    HANDLE write_end = nullptr;
    if (capture_output) {
      SECURITY_ATTRIBUTES sa = {};
      sa.nLength = sizeof(sa);
      sa.bInheritHandle = TRUE;
      if (!CreatePipe(&read_end, &write_end, &sa, 0)) {
        std::printf("  FAIL cannot create pipe: err=%lu\n", GetLastError());
        return false;
      }
      SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);
      si.hStdOutput = write_end;
      si.hStdError = write_end;
      si.dwFlags |= STARTF_USESTDHANDLES;
    }
    pi_ = {};
    const BOOL ok = CreateProcessA(
        nullptr, mutable_line.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, nullptr, &si, &pi_);
    if (write_end != nullptr) {
      CloseHandle(write_end); // the child keeps the only remaining reference
    }
    if (!ok) {
      std::printf("  FAIL cannot spawn: err=%lu\n    %s\n", GetLastError(),
                  command_line.c_str());
      if (read_end != nullptr) {
        CloseHandle(read_end);
      }
      return false;
    }
    pipe_read_ = read_end;
    started_ = true;
    return true;
  }

  // Adopt a PROCESS_INFORMATION from winraii's create_process(); from here on
  // the handles belong to this object and are closed by finish().
  bool adopt(const PROCESS_INFORMATION &pi) {
    pi_ = pi;
    started_ = true;
    return true;
  }

  DWORD pid() const { return pi_.dwProcessId; }
  bool started() const { return started_; }

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

  // Kill if still alive, then drain the captured output.  Call it before
  // reading output(): a live child keeps the write end open.
  void finish() {
    if (!started_) {
      return;
    }
    if (running()) {
      TerminateProcess(pi_.hProcess, 0xBED);
      wait(std::chrono::milliseconds(5000));
    }
    drain();
    CloseHandle(pi_.hThread);
    CloseHandle(pi_.hProcess);
    pi_ = {};
    started_ = false;
  }

  const std::string &output() const { return output_; }

private:
  void drain() {
    if (pipe_read_ == nullptr) {
      return;
    }
    char buf[1024];
    DWORD n = 0;
    while (ReadFile(pipe_read_, buf, sizeof(buf), &n, nullptr) != 0 && n > 0) {
      output_.append(buf, n);
    }
    CloseHandle(pipe_read_);
    pipe_read_ = nullptr;
  }

  PROCESS_INFORMATION pi_ = {};
  bool started_ = false;
  HANDLE pipe_read_ = nullptr;
  std::string output_;
};

// (not named quoted(): that collides with std::quoted once <iomanip> leaks in)
std::string quote_arg(const std::string &text) {
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
  return exe_dir() + ENCAPSULE_E2E_DUMMY_NAME;
}

std::string dummy_command(const std::string &exe, const std::string &host,
                          std::uint16_t port, int deadline_ms,
                          const std::string &sentinel, bool socks5) {
  std::string cmd = quote_arg(exe) + " --host " + host + " --port " +
                     std::to_string(port) + " --interval-ms " +
                     std::to_string(kIntervalMs) + " --deadline-ms " +
                     std::to_string(deadline_ms) + " --sentinel " +
                     quote_arg(sentinel);
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

// One inject-and-connect scenario against a fresh relay: the decoy hammers an
// unroutable address, encapsule-cli injects encapsule-injectee.dll into it and
// points it at this relay, and the relay asserts on the CONNECT the injectee
// actually put on the wire.  A fresh relay per case matters, because it serves
// one session at a time, and so does a fresh decoy pid.
void injection_case(const char *label, const std::string &decoy_host,
                    std::uint16_t decoy_port, char expect_atyp) {
  const int failures_before = test_failures;
  const std::string sentinel = std::string("E2E-INJECT-") + label;

  e2e::socks5_test_server server;
  CHECK(server.port() != 0);
  std::printf("  [%s] relay %s:%u, decoy %s:%u\n", label,
              server.address().c_str(), static_cast<unsigned>(server.port()),
              decoy_host.c_str(), decoy_port);

  // No --socks5 here: the injectee is what has to add the wrapping.
  const std::string decoy_cmd =
      dummy_command(dummy_path(), decoy_host, decoy_port, kDecoyDeadlineMs,
                    sentinel, false);
  const std::optional<PROCESS_INFORMATION> launched =
      create_process(decoy_cmd, CREATE_NO_WINDOW);
  CHECK(launched.has_value());
  if (!launched) {
    return;
  }
  child_process decoy;
  decoy.adopt(*launched);
  std::printf("  [%s] decoy pid %lu\n", label, decoy.pid());

  // -l so the captured log names the address the injectee reported.
  child_process injector;
  const std::string injector_cmd =
      quote_arg(g_cli_path) + " -i " + std::to_string(decoy.pid()) + " -p " +
      server.address() + ":" + std::to_string(server.port()) + " -l";
  const bool spawned_cli = injector.spawn(injector_cmd, true);
  CHECK(spawned_cli);
  if (!spawned_cli) {
    decoy.finish();
    return;
  }
  std::printf("  [%s] cli pid %lu\n", label, injector.pid());

  const bool saw_connect = server.wait_for_request_count(
      1, std::chrono::milliseconds(kInjectRecordWaitMs));
  CHECK(saw_connect);
  const auto records = server.requests();
  if (!records.empty()) {
    const auto &rec = records.front();
    CHECK_EQ(static_cast<int>(rec.atyp), static_cast<int>(expect_atyp));
    CHECK_EQ(rec.addr, decoy_host);
    CHECK_EQ(static_cast<int>(rec.port), static_cast<int>(decoy_port));
    std::printf("  [%s] CONNECT %s(%s):%u\n", label,
                e2e::atyp_name(rec.atyp).c_str(), rec.addr.c_str(),
                static_cast<unsigned>(rec.port));
  }

  // The sentinel surviving the tunnel is the round-trip proof: the decoy exits
  // 0 as soon as one comes back, 3 if none ever does.
  const bool reported =
      decoy.wait(std::chrono::milliseconds(kInjectDecoyWaitMs));
  CHECK(reported);
  CHECK_EQ(static_cast<int>(decoy.exit_code()), 0);
  CHECK(server.echoed_round_trips() >= 1);

  // Both children are killed and closed here, on every path; the injected DLL
  // is never unloaded (the injectee unloads itself, that is its business).
  injector.finish();
  decoy.finish();

  if (test_failures > failures_before) {
    std::printf("  [%s] FAILED after %zu CONNECT(s), %zu echo(s)\n", label,
                records.size(), server.echoed_round_trips());
    for (std::size_t i = 0; i < records.size(); ++i) {
      const auto &rec = records[i];
      std::printf("    #%zu %s(%s):%u\n", i, e2e::atyp_name(rec.atyp).c_str(),
                  rec.addr.c_str(), static_cast<unsigned>(rec.port));
    }
    std::printf("  ---- encapsule-cli output ----\n%s"
                "  ---- end of encapsule-cli output ----\n",
                injector.output().c_str());
  }
}

// RFC 5737 TEST-NET-3: unroutable by reservation, so a connect() that
// succeeds can only have come from the hook sending it to the relay.
void inject_ipv4_decoy() {
  injection_case("ipv4", "203.0.113.7", 8080, SOCKS_IPV4);
}

// P4-1: revisit IPv6 byte order
//
// The IPv6 decoy case ([2001:db8::1]:9090, atyp=4) cannot be asserted yet:
// the decoy in tests/e2e/dummy_target.cpp dials with an AF_INET socket only
// (InetPtonA, then gethostbyname), so a v6 literal makes it exit 2 with
// "cannot resolve --host" before connect() ever runs.  The injectee never gets
// a request to wrap and nothing reaches the relay.  Giving the case a v6 dial
// means editing the decoy, which is outside this file's fence, so it reports
// itself as skipped rather than passed or failed.  Once the decoy can dial v6,
// assert the CURRENT byte order that the S1c winnet tests locked down here.
void inject_ipv6_decoy() {
  std::printf("  SKIP(ipv6): the decoy is AF_INET-only, so the injected "
              "[2001:db8::1]:9090 case cannot reach the relay yet; no IPv6 "
              "byte-order assertion is made (P4-1)\n");
}

int run_inject() {
  if (g_cli_path.empty() || g_dummy_override.empty()) {
    std::printf("usage: e2e_test --cli <encapsule-cli> "
                "--dummy <dummy_target>\n");
    return 2;
  }
  std::printf("  cli   = %s\n  dummy = %s\n", g_cli_path.c_str(),
              g_dummy_override.c_str());
  RUN(inject_ipv4_decoy);
  RUN(inject_ipv6_decoy);
  return test_failures;
}

} // namespace

int main(int argc, char **argv) {
  std::vector<std::string> args;
  args.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
  for (int i = 1; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }

  std::string mode;
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
      if (!take(g_cli_path)) {
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
  if (mode.empty() && (!g_cli_path.empty() || !g_dummy_override.empty())) {
    mode = "inject";
  }

  WSADATA wsa = {};
  WSAStartup(MAKEWORD(2, 2), &wsa);

  int result = 0;
  if (mode == "selfcheck") {
    run_selfcheck();
    result = test_failures;
  } else if (mode == "inject") {
    result = run_inject();
  } else {
    std::printf("usage: e2e_test --selfcheck | --inject --cli X --dummy Y\n");
    result = 2;
  }

  WSACleanup();
  return result;
}
