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

// ------------------------------------------------- in-process handshakes ---
//
// These drive the INJECTEE'S OWN client half -- src/injectee/socks5.hpp's
// socks5_handshake(SOCKET, creds) and socks5_request -- over a real AF_INET
// loopback pair against the relay above, so the P5 negotiation is proven
// against a live peer rather than a hand-computed buffer.  No injection, no
// child process: this is what --selfcheck is for.  Raw winsock on the client
// side because those functions take a SOCKET; asio boots itself on the relay
// side.  One relay per case, because it serves one session at a time.

std::string hex_dump(const void *data, std::size_t n) {
  static const char *digits = "0123456789abcdef";
  const auto *bytes = static_cast<const std::uint8_t *>(data);
  std::string out;
  for (std::size_t i = 0; i < n; ++i) {
    if (i != 0) {
      out += ' ';
    }
    out += digits[bytes[i] >> 4];
    out += digits[bytes[i] & 0xF];
  }
  return out;
}

SOCKET loopback_connect(const std::string &addr, std::uint16_t port) {
  static const bool wsa_started = [] {
    WSADATA data{};
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }();
  CHECK(wsa_started);

  const SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) {
    return INVALID_SOCKET;
  }
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  sa.sin_addr.s_addr = inet_addr(addr.c_str());
  if (sa.sin_addr.s_addr == INADDR_NONE ||
      ::connect(s, reinterpret_cast<const sockaddr *>(&sa), sizeof(sa)) ==
          SOCKET_ERROR) {
    closesocket(s);
    return INVALID_SOCKET;
  }
  return s;
}

// What the client is about to put on the wire.  The greeting is the real
// bytes, from the same builder socks5_handshake() calls; the login is named by
// its shape only -- credentials do not belong in a log, not even fake ones.
void log_client_offer(const char *label, const socks5_credentials &creds) {
  uint8_t methods[2] = {};
  std::size_t n = 0;
  if (creds.enabled()) {
    methods[n++] = SOCKS_USERNAME_PASSWORD;
    methods[n++] = SOCKS_NO_AUTHENTICATION;
  } else {
    methods[n++] = SOCKS_NO_AUTHENTICATION;
  }
  char greet[SOCKS_GREETING_MAX_SIZE] = {};
  const std::size_t gn = socks5_build_greeting(methods, n, greet);
  std::printf("  [%s] client offers %s", label, hex_dump(greet, gn).c_str());
  if (creds.enabled()) {
    std::printf(", then auth 01 u%zu p%zu", creds.username.size(),
                creds.password.size());
  }
  std::printf("\n");
}

// Runs the client half through the whole walk: greet, (negotiate), CONNECT,
// then one echoed sentinel.  Returns false if any step failed.
bool tunnel_round_trip(SOCKET s, const socks5_credentials &creds,
                       const std::string &probe) {
  if (!socks5_handshake(s, creds)) {
    std::printf("  handshake refused\n");
    return false;
  }
  sockaddr_in dst{};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(8080);
  dst.sin_addr.s_addr = inet_addr("203.0.113.7");  // TEST-NET-3, never real
  if (socks5_request(s, reinterpret_cast<const sockaddr *>(&dst)) !=
      SOCKS_SUCCESS) {
    std::printf("  CONNECT refused\n");
    return false;
  }
  if (send(s, probe.data(), static_cast<int>(probe.size()), 0) !=
      static_cast<int>(probe.size())) {
    return false;
  }
  std::vector<char> back(probe.size(), '\0');
  const int got = recv(s, back.data(), static_cast<int>(back.size()), 0);
  if (got != static_cast<int>(probe.size())) {
    return false;
  }
  return std::equal(probe.begin(), probe.end(), back.begin());
}

// The relay demanded RFC 1929 and the client knew the login.
void handshake_accepts_correct_credentials() {
  e2e::socks5_test_server server;
  server.require_auth(true);
  server.set_auth_hook([](const std::string &user, const std::string &pass) {
    return user == "alice" && pass == "s3cr3t!";
  });

  const socks5_credentials creds{"alice", "s3cr3t!"};
  log_client_offer("accept", creds);

  const SOCKET s = loopback_connect(server.address(), server.port());
  CHECK(s != INVALID_SOCKET);
  if (s == INVALID_SOCKET) {
    return;
  }
  const std::string probe = "E2E-AUTH-PING";
  CHECK(tunnel_round_trip(s, creds, probe));
  closesocket(s);

  CHECK(server.wait_for_auth_count(1, std::chrono::milliseconds(5000)));
  const auto auth = server.auth_records();
  CHECK_EQ(auth.size(), std::size_t(1));
  if (auth.empty()) {
    return;
  }
  const auto &rec = auth[0];
  // Both methods offered, method 2 first (the order socks5_handshake uses)...
  const std::vector<std::uint8_t> offered{SOCKS_USERNAME_PASSWORD,
                                          SOCKS_NO_AUTHENTICATION};
  CHECK(rec.offered == offered);
  // ...the relay chose it, parsed the login, and the bytes were the real ones.
  CHECK(rec.chose_auth);
  CHECK(rec.parsed);
  CHECK(rec.ok);
  CHECK_EQ(rec.username, std::string("alice"));
  CHECK_EQ(rec.password, std::string("s3cr3t!"));
  // The CONNECT and the echo happened AFTER the login, not before.
  CHECK_EQ(server.request_count(), std::size_t(1));
  CHECK(server.echoed_round_trips() >= 1);
}

// Right username, wrong password: the client must be refused, and refused
// BEFORE it gets to ask for a CONNECT.
void handshake_refuses_wrong_password() {
  e2e::socks5_test_server server;
  server.require_auth(true);
  server.set_auth_hook([](const std::string &user, const std::string &pass) {
    return user == "alice" && pass == "s3cr3t!";
  });

  const socks5_credentials creds{"alice", "s3cr3t?"};
  log_client_offer("refuse", creds);

  const SOCKET s = loopback_connect(server.address(), server.port());
  CHECK(s != INVALID_SOCKET);
  if (s == INVALID_SOCKET) {
    return;
  }
  CHECK(!socks5_handshake(s, creds));  // relay answered {01, ff}
  closesocket(s);

  CHECK(server.wait_for_auth_count(1, std::chrono::milliseconds(5000)));
  const auto auth = server.auth_records();
  CHECK_EQ(auth.size(), std::size_t(1));
  if (auth.empty()) {
    return;
  }
  const auto &rec = auth[0];
  CHECK(rec.chose_auth);
  CHECK(rec.parsed);
  CHECK(!rec.ok);
  CHECK_EQ(rec.username, std::string("alice"));
  CHECK_EQ(rec.password, std::string("s3cr3t?"));  // what was SENT, not what
                                                   // was wanted
  CHECK_EQ(server.request_count(), std::size_t(0));  // refusal closed it
  CHECK_EQ(server.echoed_round_trips(), std::size_t(0));
}

// A client with no credentials against a proxy that demands them gets
// "no acceptable methods" -- encapsule never drops the connection through
// unauthenticated instead.
void handshake_without_credentials_is_refused() {
  e2e::socks5_test_server server;
  server.require_auth(true);  // deliberately no auth hook: refuse by default

  const socks5_credentials creds;
  log_client_offer("no-creds", creds);

  const SOCKET s = loopback_connect(server.address(), server.port());
  CHECK(s != INVALID_SOCKET);
  if (s == INVALID_SOCKET) {
    return;
  }
  CHECK(!socks5_handshake(s, creds));  // relay answered {05, ff}
  closesocket(s);

  CHECK(server.wait_for_auth_count(1, std::chrono::milliseconds(5000)));
  const auto auth = server.auth_records();
  CHECK_EQ(auth.size(), std::size_t(1));
  if (auth.empty()) {
    return;
  }
  const auto &rec = auth[0];
  const std::vector<std::uint8_t> offered{SOCKS_NO_AUTHENTICATION};
  CHECK(rec.offered == offered);
  CHECK(!rec.chose_auth);   // there was nothing to negotiate with
  CHECK(!rec.parsed);       // no login was ever sent
  CHECK(!rec.ok);
  CHECK_EQ(server.request_count(), std::size_t(0));
}

// And the compatibility case the relay has to keep answering exactly as it
// always did: method 2 offered, auth NOT required -> {05, 00}, then the normal
// no-auth walk.  This is the inject_connect path with credentials available.
void relay_picks_no_auth_when_auth_is_not_required() {
  e2e::socks5_test_server server;
  CHECK(!server.auth_required());

  const socks5_credentials creds{"alice", "s3cr3t!"};
  log_client_offer("not-required", creds);

  const SOCKET s = loopback_connect(server.address(), server.port());
  CHECK(s != INVALID_SOCKET);
  if (s == INVALID_SOCKET) {
    return;
  }
  const std::string probe = "E2E-NOAUTH-PING";
  CHECK(tunnel_round_trip(s, creds, probe));
  closesocket(s);

  CHECK(server.wait_for_auth_count(1, std::chrono::milliseconds(5000)));
  const auto auth = server.auth_records();
  CHECK_EQ(auth.size(), std::size_t(1));
  if (auth.empty()) {
    return;
  }
  const auto &rec = auth[0];
  const std::vector<std::uint8_t> offered{SOCKS_USERNAME_PASSWORD,
                                          SOCKS_NO_AUTHENTICATION};
  CHECK(rec.offered == offered);
  CHECK(!rec.chose_auth);
  CHECK(!rec.parsed);
  CHECK(rec.username.empty() && rec.password.empty());
  CHECK_EQ(server.request_count(), std::size_t(1));
  CHECK(server.echoed_round_trips() >= 1);
}

// A demanding proxy has to survive a client that sends a broken RFC 1929 body:
// answer {01, FF}, drop that session, and stay perfectly usable afterwards.
// Three shapes of wrong, then ONE good alice/s3cr3t! session on the same relay
// -- the good one is the proof nothing got contaminated.
//
// The client here is hand-rolled on purpose: socks5_handshake() only ever
// produces well-formed requests, so a bad body has to be typed out byte by
// byte.  The greeting in front of it still comes from the real builder.
void malformed_subnegotiation_is_refused_without_crash() {
  e2e::socks5_test_server server;
  server.require_auth(true);
  server.set_auth_hook([](const std::string &user, const std::string &pass) {
    return user == "alice" && pass == "s3cr3t!";
  });

  uint8_t methods[2] = {SOCKS_USERNAME_PASSWORD, SOCKS_NO_AUTHENTICATION};
  char greet[SOCKS_GREETING_MAX_SIZE] = {};
  const std::size_t greet_len = socks5_build_greeting(methods, 2, greet);
  CHECK_EQ(greet_len, std::size_t(4));  // 05 02 02 00

  const std::vector<std::pair<const char *, std::vector<char>>> broken = {
      {"wrong ver", {0x05, 0x05, 0x00, 0x00}},  // VER must be 1, not 5
      {"ulen overruns", {0x01, static_cast<char>(0xFF), 'a', 'l', 'i'}},
      {"truncated", {0x01, 0x05, 'a', 'l', 'i'}},  // stops mid-username
  };

  for (const auto &[label, body] : broken) {
    const SOCKET s = loopback_connect(server.address(), server.port());
    CHECK(s != INVALID_SOCKET);
    if (s == INVALID_SOCKET) {
      return;
    }
    // Belt and braces: the relay's own idle bound is 5s, so a stalled read is
    // slow but never hangs this test.
    DWORD rcv_ms = 10000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char *>(&rcv_ms), sizeof(rcv_ms));

    bool refused = false;
    do {
      if (send(s, greet, static_cast<int>(greet_len), 0) !=
          static_cast<int>(greet_len)) {
        break;
      }
      char choice[2] = {};
      if (recv(s, choice, 2, 0) != 2) {
        break;
      }
      if (static_cast<std::uint8_t>(choice[0]) != SOCKS_VERSION ||
          static_cast<std::uint8_t>(choice[1]) != SOCKS_USERNAME_PASSWORD) {
        break;  // the relay did not pick method 2
      }
      if (send(s, body.data(), static_cast<int>(body.size()), 0) !=
          static_cast<int>(body.size())) {
        break;
      }
      // Nothing after the partial body: the relay must see a short read.
      shutdown(s, SD_SEND);
      char verdict[2] = {};
      if (recv(s, verdict, 2, 0) != 2) {
        break;
      }
      refused = static_cast<std::uint8_t>(verdict[0]) == SOCKS_AUTH_VERSION &&
                static_cast<std::uint8_t>(verdict[1]) == SOCKS_AUTH_FAILURE;
      std::printf("  [%s] %s + %s -> relay %02x %02x\n", label,
                  hex_dump(greet, greet_len).c_str(),
                  hex_dump(body.data(), body.size()).c_str(),
                  static_cast<unsigned char>(verdict[0]),
                  static_cast<unsigned char>(verdict[1]));
    } while (false);
    closesocket(s);
    CHECK(refused);
  }

  // Three greetings, all seen, none of them parsed or accepted.
  CHECK(server.wait_for_auth_count(broken.size(),
                                   std::chrono::milliseconds(10000)));
  const auto auth = server.auth_records();
  CHECK_EQ(auth.size(), broken.size());
  const std::vector<std::uint8_t> offered{SOCKS_USERNAME_PASSWORD,
                                          SOCKS_NO_AUTHENTICATION};
  for (const auto &rec : auth) {
    CHECK(rec.offered == offered);  // the greeting itself was read fine
    CHECK(rec.chose_auth);          // and answered {05, 02}
    CHECK(!rec.parsed);             // the body never validated
    CHECK(!rec.ok);                 // so it was refused
    CHECK(rec.password.empty());    // nothing complete was ever stored
  }
  // Not one of them got to ask for a CONNECT.
  CHECK_EQ(server.request_count(), std::size_t(0));
  CHECK_EQ(server.echoed_round_trips(), std::size_t(0));

  // The relay is still alive: a well-formed login on the SAME instance works
  // end to end, right after three malformed ones.
  const socks5_credentials creds{"alice", "s3cr3t!"};
  const SOCKET good = loopback_connect(server.address(), server.port());
  CHECK(good != INVALID_SOCKET);
  if (good != INVALID_SOCKET) {
    CHECK(tunnel_round_trip(good, creds, "E2E-AFTER-MALFORMED"));
    closesocket(good);
  }
  CHECK(server.wait_for_auth_count(broken.size() + 1,
                                   std::chrono::milliseconds(10000)));
  const auto after = server.auth_records();
  CHECK_EQ(after.size(), broken.size() + 1);
  if (after.size() == broken.size() + 1) {
    CHECK(after.back().parsed);        // the good body did parse
    CHECK(after.back().ok);
    CHECK_EQ(after.back().username, std::string("alice"));
    CHECK_EQ(after.back().password, std::string("s3cr3t!"));
  }
  CHECK_EQ(server.request_count(), std::size_t(1));  // its CONNECT landed
  CHECK(server.echoed_round_trips() >= 1);
}

void run_selfcheck() {
  RUN(relay_records_connect_and_echoes);
  RUN(on_connect_hook_can_refuse);
  // The P5 negotiation, client half against relay half, in this process.
  RUN(handshake_accepts_correct_credentials);
  RUN(handshake_refuses_wrong_password);
  RUN(handshake_without_credentials_is_refused);
  RUN(relay_picks_no_auth_when_auth_is_not_required);
  RUN(malformed_subnegotiation_is_refused_without_crash);
}

// ------------------------------------------------------------------ inject --

// Optional RFC 1929 login for an injection case.  The default is exactly the
// pre-P5 shape: no credentials, a bare host:port on -p, and the relay left
// without any demand for authentication.  user/pass is what the CLI hands the
// injectee; accept_user/accept_pass is what the RELAY's hook will agree to --
// the fail-closed case runs the two apart on purpose.
struct inject_creds {
  const char *user = nullptr;
  const char *pass = nullptr;
  const char *accept_user = nullptr;
  const char *accept_pass = nullptr;
  bool refused = false;  // the login is expected to be turned down
  int decoy_deadline_ms = kDecoyDeadlineMs;
};

constexpr int kAuthDecoyDeadlineMs = 18000;  // bounds the fail-closed sub-case

// One inject-and-connect scenario against a fresh relay: the decoy hammers an
// unroutable address, encapsule-cli injects encapsule-injectee.dll into it and
// points it at this relay, and the relay asserts on the CONNECT the injectee
// actually put on the wire.  A fresh relay per case matters, because it serves
// one session at a time, and so does a fresh decoy pid.
void injection_case(const char *label, const std::string &decoy_host,
                    std::uint16_t decoy_port, char expect_atyp,
                    const inject_creds &creds = inject_creds{}) {
  const int failures_before = test_failures;
  const std::string sentinel = std::string("E2E-INJECT-") + label;
  const bool creds_in_play = creds.user != nullptr;

  e2e::socks5_test_server server;
  CHECK(server.port() != 0);
  if (creds_in_play) {
    server.require_auth(true);
    const std::string want_user = creds.accept_user ? creds.accept_user : "";
    const std::string want_pass =
        creds.accept_pass ? creds.accept_pass : "";
    // The judge lives here, not in the injectee: what the login IS never gets
    // printed, only whether it passed and how long each field was.
    server.set_auth_hook([want_user, want_pass](const std::string &user,
                                                const std::string &pass) {
      return user == want_user && pass == want_pass;
    });
  }
  std::printf("  [%s] relay %s:%u, decoy %s:%u\n", label,
              server.address().c_str(), static_cast<unsigned>(server.port()),
              decoy_host.c_str(), decoy_port);

  // No --socks5 here: the injectee is what has to add the wrapping.
  const std::string decoy_cmd =
      dummy_command(dummy_path(), decoy_host, decoy_port,
                    creds.decoy_deadline_ms, sentinel, false);
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
  // -p takes [user[:pass]@]host:port; the address stays numeric, so the
  // brackets the grammar allows for IPv6 are not needed here.
  std::string proxy_arg =
      server.address() + ":" + std::to_string(server.port());
  if (creds_in_play) {
    proxy_arg = std::string(creds.user) + ":" + creds.pass + "@" + proxy_arg;
  }
  const std::string injector_cmd =
      quote_arg(g_cli_path) + " -i " + std::to_string(decoy.pid()) + " -p " +
      proxy_arg + " -l";
  const bool spawned_cli = injector.spawn(injector_cmd, true);
  CHECK(spawned_cli);
  if (!spawned_cli) {
    decoy.finish();
    return;
  }
  std::printf("  [%s] cli pid %lu\n", label, injector.pid());

  // On the wire the login comes first, so the auth record is read before the
  // CONNECT is waited for.  Bytes are asserted, lengths are printed.
  const bool refused_login = creds_in_play && creds.refused;
  if (creds_in_play) {
    const bool saw_login = server.wait_for_auth_count(
        1, std::chrono::milliseconds(kInjectRecordWaitMs));
    CHECK(saw_login);
    const auto auth = server.auth_records();
    CHECK_EQ(auth.size(), std::size_t(1));
    if (!auth.empty()) {
      const auto &rec = auth.back();
      const std::vector<std::uint8_t> offered{SOCKS_USERNAME_PASSWORD,
                                              SOCKS_NO_AUTHENTICATION};
      CHECK(rec.offered == offered);  // the DLL really offered method 2
      CHECK(rec.chose_auth);          // the relay picked it
      CHECK(rec.parsed);              // a complete 1929 request arrived
      CHECK_EQ(rec.username, std::string(creds.user));  // exact bytes on both
      CHECK_EQ(rec.password, std::string(creds.pass));
      CHECK_EQ(rec.ok, !refused_login);
      std::printf("  [%s] 1929 %s: offered [%s] user=%zu pass=%zu\n", label,
                  rec.ok ? "accepted" : "refused",
                  e2e::method_list_text(rec.offered).c_str(),
                  rec.username.size(), rec.password.size());
    }
  }

  // A refused login must never become a CONNECT: the caller waits out the whole
  // decoy window below and the CONNECT count still has to read zero.
  const bool saw_connect =
      refused_login
          ? true
          : server.wait_for_request_count(
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
  if (refused_login) {
    // Fail closed, which is the whole point of this sub-case: the proxy turned
    // the login down, so the target got WSAECONNREFUSED and never reached its
    // destination directly.  Exit 3 alone does not prove that (an un-injected
    // decoy exits 3 as well) -- the refused 1929 record above does, because
    // only the injectee can put it on this relay.
    CHECK_EQ(static_cast<int>(decoy.exit_code()), kExitNoRoundTrip);
    CHECK_EQ(server.request_count(), std::size_t(0));
    CHECK_EQ(server.echoed_round_trips(), std::size_t(0));
  } else {
    CHECK_EQ(static_cast<int>(decoy.exit_code()), 0);
    CHECK(server.echoed_round_trips() >= 1);
  }

  // Read before the handles go away: after finish() the exit code cannot be
  // asked for anymore, and an unreadable one prints as this helper's sentinel.
  const unsigned long decoy_exit = decoy.exit_code();

  // Both children are killed and closed here, on every path; the injected DLL
  // is never unloaded (the injectee unloads itself, that is its business).
  injector.finish();
  decoy.finish();

  if (test_failures > failures_before) {
    std::printf("  [%s] FAILED after %zu CONNECT(s), %zu echo(s), %zu login(s)\n",
                label, records.size(), server.echoed_round_trips(),
                server.auth_count());
    // The exit code tells an unhooked decoy (3, it ran out its deadline) from
    // one that died inside the injected code (an exception code).
    std::printf("  [%s] decoy exit 0x%08lx\n", label, decoy_exit);
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
// P5 S6b: credentials through the real injection path -- the CLI parses
// -p user:pass@host:port, the server ships them in InjectorConfig fields 4/5,
// the injected DLL negotiates RFC 1929, and this relay judges the login.
void inject_auth_accepted() {
  injection_case("auth-pass", "203.0.113.7", 8080, SOCKS_IPV4,
                 inject_creds{"alice", "s3cr3t!", "alice", "s3cr3t!", false,
                              kAuthDecoyDeadlineMs});
}

// Same login from the same code path; only the relay's expectation differs, so
// what is under test is the response to a refusal.
void inject_auth_refused() {
  injection_case("auth-refused", "203.0.113.7", 8080, SOCKS_IPV4,
                 inject_creds{"alice", "s3cr3t!", "alice",
                              "not-the-real-secret", true,
                              kAuthDecoyDeadlineMs});
}

void inject_ipv6_decoy() {
  std::printf("  SKIP(ipv6): the decoy is AF_INET-only, so the injected "
              "[2001:db8::1]:9090 case cannot reach the relay yet; no IPv6 "
              "byte-order assertion is made (P4-1)\n");
}

// Both auth sub-cases, sequentially, in one process.  Each brings its own
// relay and decoy, so the wall clock is roughly 20s + 20s -- well inside the
// 120s the CTest registration allows.
int run_inject_auth() {
  if (g_cli_path.empty() || g_dummy_override.empty()) {
    std::printf("usage: e2e_test --inject-auth --cli <encapsule-cli> "
                "--dummy <dummy_target>\n");
    return 2;
  }
  std::printf("  cli   = %s\n  dummy = %s\n", g_cli_path.c_str(),
              g_dummy_override.c_str());
  RUN(inject_auth_accepted);
  RUN(inject_auth_refused);
  return test_failures;
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
    } else if (flag == "--inject-auth") {
      mode = "inject_auth";
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
      std::printf("usage: e2e_test --selfcheck | --inject | --inject-auth"
                  " --cli X --dummy Y\n");
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
  } else if (mode == "inject_auth") {
    result = run_inject_auth();
  } else if (mode == "inject") {
    result = run_inject();
  } else {
    std::printf("usage: e2e_test --selfcheck | --inject | --inject-auth"
                " --cli X --dummy Y\n");
    result = 2;
  }

  WSACleanup();
  return result;
}
