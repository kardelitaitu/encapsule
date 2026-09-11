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

// The decoy process for the end-to-end smoke test: a plain winsock TCP client
// with no dependency on the product code, so nothing here can mask a broken
// injectee.  It hammers host:port every --interval-ms until --deadline-ms has
// passed and reports whether a sentinel byte string survived the round trip.
//
//   --host <addr>        who to dial              (default 127.0.0.1)
//   --port <port>        port to dial             (required)
//   --interval-ms <n>    delay between attempts   (default 300)
//   --deadline-ms <n>    give up after this long  (default 20000)
//   --sentinel <bytes>   payload to echo-probe    (default E2E-SENTINEL)
//   --socks5             speak the socks5 client handshake first, asking the
//                        peer to CONNECT to this very host:port.  Used by the
//                        loopback self-check, where this process talks to the
//                        relay directly.  Left out when the run relies on the
//                        injectee to add the handshake by hooking connect().
//
// Exit code: 0 once at least one round trip succeeded, 3 if none did, 2 for
// bad usage or a socket it could not even create.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>

#include <WinSock2.h>
#include <WS2tcpip.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr char kDefaultSentinel[] = "E2E-SENTINEL";
constexpr int kIoTimeoutMs = 2000;

struct options {
  std::string host = "127.0.0.1";
  std::string port;
  std::string sentinel = kDefaultSentinel;
  long interval_ms = 300;
  long deadline_ms = 20000;
  bool socks5 = false;
};

void print_usage() {
  std::printf(
      "usage: dummy_target --port <n> [--host <addr>] [--interval-ms <n>]\n"
      "                  [--deadline-ms <n>] [--sentinel <s>] [--socks5]\n");
}

bool parse_long(const char *text, long &out) {
  char *end = nullptr;
  const long value = std::strtol(text, &end, 10);
  if (end == text || (end && *end != '\0')) {
    return false;
  }
  out = value;
  return true;
}

bool parse_args(int argc, char **argv, options &opt, std::string &error) {
  for (int i = 1; i < argc; ++i) {
    const std::string flag = argv[i];
    auto value = [&](std::string &slot) {
      if (i + 1 >= argc) {
        error = flag + " needs a value";
        return false;
      }
      slot = argv[++i];
      return true;
    };
    if (flag == "--socks5") {
      opt.socks5 = true;
      continue;
    }
    std::string slot;
    if (!value(slot)) {
      return false;
    }
    if (flag == "--host") {
      opt.host = slot;
    } else if (flag == "--port") {
      opt.port = slot;
    } else if (flag == "--sentinel") {
      opt.sentinel = slot;
    } else if (flag == "--interval-ms") {
      if (!parse_long(slot.c_str(), opt.interval_ms)) {
        error = flag + " wants a number";
        return false;
      }
    } else if (flag == "--deadline-ms") {
      if (!parse_long(slot.c_str(), opt.deadline_ms)) {
        error = flag + " wants a number";
        return false;
      }
    } else {
      error = "unknown argument " + flag;
      return false;
    }
  }
  if (opt.port.empty()) {
    error = "--port is required";
    return false;
  }
  if (opt.sentinel.empty()) {
    error = "--sentinel must not be empty";
    return false;
  }
  if (opt.interval_ms < 1) {
    opt.interval_ms = 1;
  }
  return true;
}

// The client half of the no-auth socks5 handshake, spelled out byte by byte
// on purpose: it is the independent check that the relay and src/injectee
// agree on the wire format.
bool socks5_handshake(SOCKET s, const std::string &host,
                      const std::string &port) {
  const char greeting[3] = {5, 1, 0}; // VER, NMETHODS, NO-AUTH
  if (send(s, greeting, sizeof(greeting), 0) != sizeof(greeting)) {
    std::printf("[dummy] socks5 greeting send failed (%d)\n",
                WSAGetLastError());
    return false;
  }

  char reply[2] = {};
  if (recv(s, reply, sizeof(reply), MSG_WAITALL) != sizeof(reply) ||
      reply[0] != 5 || reply[1] != 0) {
    std::printf("[dummy] socks5 greeting refused\n");
    return false;
  }

  sockaddr_in target = {};
  target.sin_family = AF_INET;
  target.sin_port = htons(static_cast<u_short>(std::atoi(port.c_str())));
  if (InetPtonA(AF_INET, host.c_str(), &target.sin_addr) != 1) {
    std::printf("[dummy] --host %s is not numeric; socks5 mode needs an IP\n",
                host.c_str());
    return false;
  }

  char request[10] = {5, 1, 0, 1}; // VER, CONNECT, RSV, ATYP=IPv4
  std::memcpy(request + 4, &target.sin_addr.s_addr, 4);
  std::memcpy(request + 8, &target.sin_port, 2);
  if (send(s, request, sizeof(request), 0) != sizeof(request)) {
    std::printf("[dummy] socks5 request send failed (%d)\n", WSAGetLastError());
    return false;
  }

  char complete[10] = {};
  if (recv(s, complete, sizeof(complete), MSG_WAITALL) != sizeof(complete)) {
    std::printf("[dummy] socks5 reply truncated\n");
    return false;
  }
  if (complete[1] != 0) {
    std::printf("[dummy] socks5 CONNECT refused by relay (rep=%d)\n",
                static_cast<unsigned char>(complete[1]));
    return false;
  }
  return true;
}

bool exchange_sentinel(SOCKET s, const std::string &sentinel) {
  if (send(s, sentinel.data(), static_cast<int>(sentinel.size()), 0) !=
      static_cast<int>(sentinel.size())) {
    std::printf("[dummy] sentinel send failed (%d)\n", WSAGetLastError());
    return false;
  }

  std::vector<char> echoed(sentinel.size(), '\0');
  std::size_t got = 0;
  while (got < echoed.size()) {
    const int n = recv(s, echoed.data() + got,
                       static_cast<int>(echoed.size() - got), 0);
    if (n <= 0) {
      std::printf("[dummy] sentinel echo missing (%d of %zu bytes, err %d)\n",
                  static_cast<int>(got), echoed.size(), WSAGetLastError());
      return false;
    }
    got += static_cast<std::size_t>(n);
  }
  if (std::memcmp(echoed.data(), sentinel.data(), sentinel.size()) != 0) {
    std::printf("[dummy] sentinel echo mismatch\n");
    return false;
  }
  std::printf("[dummy] round trip ok: %s\n", sentinel.c_str());
  return true;
}

bool resolve(const options &opt, sockaddr_in &target) {
  target = {};
  target.sin_family = AF_INET;
  target.sin_port = htons(static_cast<u_short>(std::atoi(opt.port.c_str())));
  if (InetPtonA(AF_INET, opt.host.c_str(), &target.sin_addr) == 1) {
    return true;
  }
  hostent *he = gethostbyname(opt.host.c_str());
  if (!he || he->h_addrtype != AF_INET || !he->h_addr_list[0]) {
    return false;
  }
  std::memcpy(&target.sin_addr, he->h_addr_list[0], sizeof(target.sin_addr));
  return true;
}

} // namespace

int main(int argc, char **argv) {
  options opt;
  std::string error;
  if (!parse_args(argc, argv, opt, error)) {
    std::printf("[dummy] %s\n", error.c_str());
    print_usage();
    return 2;
  }

  WSADATA data;
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
    std::printf("[dummy] WSAStartup failed\n");
    return 2;
  }

  sockaddr_in target;
  if (!resolve(opt, target)) {
    std::printf("[dummy] cannot resolve --host %s\n", opt.host.c_str());
    WSACleanup();
    return 2;
  }

  const ULONGLONG start = GetTickCount64();
  int attempts = 0;
  int round_trips = 0;
  while (GetTickCount64() - start < static_cast<ULONGLONG>(opt.deadline_ms)) {
    ++attempts;
    const SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
      std::printf("[dummy] socket() failed (%d)\n", WSAGetLastError());
      WSACleanup();
      return 2;
    }
    DWORD timeout = static_cast<DWORD>(kIoTimeoutMs);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char *>(&timeout),
               sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char *>(&timeout),
               sizeof(timeout));

    const bool connected = ::connect(
        s, reinterpret_cast<sockaddr *>(&target), sizeof(target)) == 0;
    if (connected) {
      bool ok = !opt.socks5 || socks5_handshake(s, opt.host, opt.port);
      if (ok && exchange_sentinel(s, opt.sentinel)) {
        ++round_trips;
      }
    } else {
      std::printf("[dummy] attempt %d: connect failed (%d)\n", attempts,
                  WSAGetLastError());
    }
    closesocket(s);
    if (round_trips > 0) {
      break;
    }
    Sleep(static_cast<DWORD>(opt.interval_ms));
  }

  std::printf("[dummy] attempts=%d round_trips=%d elapsed=%llums\n", attempts,
              round_trips,
              static_cast<unsigned long long>(GetTickCount64() - start));
  WSACleanup();
  return round_trips > 0 ? 0 : 3;
}
