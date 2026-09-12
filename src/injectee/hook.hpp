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

#ifndef ENCAPSULE_INJECTEE_HOOK
#define ENCAPSULE_INJECTEE_HOOK

#include "client.hpp"
#include "minhook.hpp"
#include "socks5.hpp"
#include "utils.hpp"
#include "winnet.hpp"
#include <map>
#include <mutex>
#include <optional>
#include <protopuf/fixed_string.h>
#include <string>

inline blocking_queue<InjecteeMessage> *queue = nullptr;
inline injectee_config *config = nullptr;
inline std::map<SOCKET, bool> *nbio_map = nullptr;

// guards nbio_map; never hold it across winsock calls (detour reentry)
inline std::mutex nbio_mutex;

inline void nbio_store(SOCKET s, bool nb) {
  if (!nbio_map) {
    return;
  }
  std::lock_guard<std::mutex> lock(nbio_mutex);
  (*nbio_map)[s] = nb;
}

inline std::optional<bool> nbio_load(SOCKET s) {
  if (!nbio_map) {
    return std::nullopt;
  }
  std::lock_guard<std::mutex> lock(nbio_mutex);
  if (auto iter = nbio_map->find(s); iter != nbio_map->end()) {
    return iter->second;
  }
  return std::nullopt;
}

inline void nbio_erase(SOCKET s) {
  if (!nbio_map) {
    return;
  }
  std::lock_guard<std::mutex> lock(nbio_mutex);
  nbio_map->erase(s);
}

// deadline for the socks5 handshake performed inside blocking_scope; a
// timed-out handshake fails the connect (never silently direct-connects)
inline constexpr std::uint32_t SOCKS_HANDSHAKE_TIMEOUT_MS = 3000;

struct hook_ioctlsocket : minhook::api<ioctlsocket, hook_ioctlsocket> {
  static int WSAAPI detour(SOCKET s, long cmd, u_long FAR *argp) {
    if (nbio_map && cmd == FIONBIO) {
      nbio_store(s, *argp != 0);
    }

    return original(s, cmd, argp);
  }
};
struct hook_WSAAsyncSelect : minhook::api<WSAAsyncSelect, hook_WSAAsyncSelect> {
  static int WSAAPI detour(SOCKET s, HWND hWnd, u_int wMsg, long lEvent) {
    if (nbio_map) {
      nbio_store(s, true);
    }

    return original(s, hWnd, wMsg, lEvent);
  }
};
struct hook_WSAEventSelect : minhook::api<WSAEventSelect, hook_WSAEventSelect> {
  static int WSAAPI detour(SOCKET s, WSAEVENT hEventObject,
                           long lNetworkEvents) {
    if (nbio_map) {
      nbio_store(s, true);
    }

    return original(s, hEventObject, lNetworkEvents);
  }
};

// forget the per-socket non-blocking state when the target closes the
// socket, so nbio_map cannot grow without bound
struct hook_closesocket : minhook::api<closesocket, hook_closesocket> {
  static int WSAAPI detour(SOCKET s) {
    nbio_erase(s);
    return original(s);
  }
};

struct blocking_scope {
  SOCKET sock;
  DWORD old_rcvtimeo = 0;
  DWORD old_sndtimeo = 0;

  blocking_scope(SOCKET s, std::uint32_t timeout_ms) : sock(s) {
    int size = sizeof(DWORD);
    getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&old_rcvtimeo, &size);
    size = sizeof(DWORD);
    getsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&old_sndtimeo, &size);

    const DWORD timeout = timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
               sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout,
               sizeof(timeout));

    u_long nb = FALSE;
    hook_ioctlsocket::original(sock, FIONBIO, &nb);
  }
  ~blocking_scope() {
    bool nb = false;
    if (auto saved = nbio_load(sock)) {
      nb = *saved;
    }
    u_long value = nb ? TRUE : FALSE;
    hook_ioctlsocket::original(sock, FIONBIO, &value);

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&old_rcvtimeo,
               sizeof(old_rcvtimeo));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&old_sndtimeo,
               sizeof(old_sndtimeo));
  }

  blocking_scope(const blocking_scope &) = delete;
  blocking_scope(blocking_scope &&) = delete;
};

// fail the proxied connect: tear the proxy link down and leave a fresh
// error code behind - a handshake timeout surfaces as WSAETIMEDOUT, any
// other handshake failure as WSAECONNREFUSED, never a stale error
inline int fail_proxied_connect(SOCKET s, int ret) {
  const int err = WSAGetLastError();
  shutdown(s, SD_BOTH);
  WSASetLastError(err == WSAETIMEDOUT ? WSAETIMEDOUT : WSAECONNREFUSED);
  return ret;
}

// Is this a TCP stream socket?  Everything below is a TCP machine: the
// proxification re-points the caller's socket at the proxy, then speaks the
// socks5 conversation -- send, wait, recv -- over it.  A SOCK_DGRAM socket
// cannot answer that conversation no matter where it is pointed: connect() on
// one only records a peer.  Before this check existed, that meant the
// greeting left as one datagram, nothing ever came back, blocking_scope
// waited out the handshake timeout, and fail_proxied_connect shut the socket
// down -- an application lost a perfectly good datagram socket to a
// proxification that could not have worked.  So the four routing detours ask
// this first and hand anything else straight to the original: datagrams stay
// exactly as reachable as they were before the capsule existed, and get a
// relay of their own in P7 rather than a TCP one borrowed.
//
// getsockopt is not one of the hooked APIs (hook_create_all at the bottom of
// this file: connect, WSAConnect, WSAConnectByList, WSAConnectByName{A,W},
// CreateProcess{A,W}, ioctlsocket, WSAAsyncSelect, WSAEventSelect,
// closesocket, ConnectEx), so this is the real winsock entry point and it
// cannot re-enter a detour -- blocking_scope above already reads
// SO_RCVTIMEO/SO_SNDTIMEO the same way from inside these very functions.
// Nothing is cached: a getsockopt per connect sits next to the connect itself
// and the sockets here are never in a per-datagram loop.
//
// A getsockopt that fails -- a bad descriptor, a provider that will not say
// -- reads as "not a stream", which declines to route rather than running a
// TCP handshake over something unknown; the original then gives the caller
// the error it actually expects, instead of one this hook invented.
inline bool socket_is_stream(SOCKET s) {
  int type = 0;
  int size = sizeof(type);
  if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&type, &size) != 0) {
    return false;
  }

  return type == SOCK_STREAM;
}

template <auto F, pp::basic_fixed_string N>
struct hook_connect_fn : minhook::api<F, hook_connect_fn<F, N>> {
  using base = minhook::api<F, hook_connect_fn<F, N>>;

  template <typename... T>
  static int WSAAPI detour(SOCKET s, const sockaddr *name, int namelen,
                           T... args) {
    // A datagram socket is not routed, whatever else is true of it.
    if (!socket_is_stream(s)) {
      return base::original(s, name, namelen, args...);
    }

    if (is_inet(name) && config && !is_localhost(name)) {
      auto cfg = config->get();
      if (auto v = to_ip_addr(name)) {

        auto proxy = cfg["addr"_f];
        auto log = cfg["log"_f];
        if (queue && log && log.value()) {
          queue->push(create_message<InjecteeMessage, "connect">(
              InjecteeConnect{(std::uint32_t)s, *v, proxy, N}));
        }

        if (proxy) {
          if (auto [addr, addr_size] = to_sockaddr(*proxy);
              addr && !sockequal(addr.get(), name)) {
            blocking_scope scope(s, SOCKS_HANDSHAKE_TIMEOUT_MS);

            auto ret = base::original(s, addr.get(), addr_size, args...);
            if (ret)
              return ret;

            if (!socks5_handshake(s, socks5_credentials_from(cfg))) {
              return fail_proxied_connect(s, SOCKET_ERROR);
            }
            if (socks5_request(s, name) != SOCKS_SUCCESS) {
              return fail_proxied_connect(s, SOCKET_ERROR);
            }

            return 0;
          }
        }
      }
    }
    return base::original(s, name, namelen, args...);
  }
};

struct hook_connect : hook_connect_fn<connect, "connect"> {};
struct hook_WSAConnect : hook_connect_fn<WSAConnect, "WSAConnect"> {};

struct hook_WSAConnectByList
    : minhook::api<WSAConnectByList, hook_WSAConnectByList> {
  static BOOL PASCAL detour(SOCKET s, PSOCKET_ADDRESS_LIST SocketAddress,
                            LPDWORD LocalAddressLength, LPSOCKADDR LocalAddress,
                            LPDWORD RemoteAddressLength,
                            LPSOCKADDR RemoteAddress, const timeval *timeout,
                            LPWSAOVERLAPPED Reserved) {
    // Not a stream: straight through -- including past the "a proxy is set,
    // so refuse" fall-out at the bottom of this block, which is a TCP
    // decision and none of a datagram socket's business.
    if (!socket_is_stream(s)) {
      return original(s, SocketAddress, LocalAddressLength, LocalAddress,
                      RemoteAddressLength, RemoteAddress, timeout, Reserved);
    }

    if (config) {
      auto cfg = config->get();
      auto proxy = cfg["addr"_f];
      auto log = cfg["log"_f];

      for (size_t i = 0; i < SocketAddress->iAddressCount; ++i) {
        LPSOCKADDR name = SocketAddress->Address[i].lpSockaddr;

        if (is_inet(name) && !is_localhost(name)) {
          if (auto v = to_ip_addr(name)) {

            if (queue && log && log.value()) {
              queue->push(
                  create_message<InjecteeMessage, "connect">(InjecteeConnect{
                      (std::uint32_t)s, *v, proxy, "WSAConnectByList"}));
            }

            if (proxy) {
              if (auto [addr, addr_size] = to_sockaddr(*proxy);
                  addr && !sockequal(addr.get(), name)) {
                blocking_scope scope(s, SOCKS_HANDSHAKE_TIMEOUT_MS);

                auto ret = hook_connect::original(s, addr.get(), addr_size);
                if (ret)
                  return ret;

                if (!socks5_handshake(s, socks5_credentials_from(cfg))) {
                  fail_proxied_connect(s, FALSE);
                  continue;
                }
                if (socks5_request(s, name) != SOCKS_SUCCESS) {
                  fail_proxied_connect(s, FALSE);
                  continue;
                }

                *RemoteAddressLength =
                    std::min(*RemoteAddressLength, (DWORD)addr_size);
                memcpy(RemoteAddress, addr.get(), *RemoteAddressLength);

                sockaddr local;
                int local_size = sizeof(local);
                getsockname(s, &local, &local_size);

                *LocalAddressLength =
                    std::min(*LocalAddressLength, (DWORD)local_size);
                memcpy(LocalAddress, &local, *LocalAddressLength);

                return TRUE;
              }
            }
          }
        }
      }

      if (proxy)
        return FALSE;
    }

    return original(s, SocketAddress, LocalAddressLength, LocalAddress,
                    RemoteAddressLength, RemoteAddress, timeout, Reserved);
  }
};

inline const std::map<std::string, std::uint16_t> service_map = {
#define X(name, port, _) {name, port},
#include "services.inc"
#undef X
};

// A service name is turned into a port by three sources, tried in this order.
//
// The third is the one that matters.  WSAConnectByName is handed a service,
// not a port, and every service this function cannot name used to make its
// detour fall through to the original call -- which resolves the name its own
// way and connects, direct and unproxied.  "some-exotic-svc", or any name the
// IANA list compiled in above does not carry, leaked that way:
// the table is a fast path, it is not allowed to be the last word.
inline std::optional<std::uint16_t>
service_to_port(const std::string &servicename) {
  // Numeric.  Accumulated rather than handed to std::stoi: stoi throws on
  // "999999999" and on "" (std::all_of calls the empty string all-digit), and
  // an exception escaping a detour is the host process dying.  The bounds are
  // the same ones parse_proxy_url applies, "0" included -- not a port.
  if (!servicename.empty() &&
      servicename.size() <= proxy_port_max_length &&
      all_of_digit(servicename)) {
    std::uint32_t port = 0;
    for (const char digit : servicename) {
      port = port * 10 + static_cast<std::uint32_t>(digit - '0');
    }
    if (port > 0 && port <= 65535) {
      return static_cast<std::uint16_t>(port);
    }
  }

  // The compile-time table.  Its keys are the lower-case IANA names, while
  // Windows matches service names without regard to case, so the lookup is
  // folded the same way -- ASCII only, which is all a service name is.
  std::string folded;
  folded.reserve(servicename.size());
  for (const char c : servicename) {
    const bool upper = c >= 'A' && c <= 'Z';
    folded.push_back(upper ? static_cast<char>(c - 'A' + 'a') : c);
  }
  if (auto iter = service_map.find(folded); iter != service_map.end()) {
    return iter->second;
  }

  // The OS services database: the same registry/HOSTS/Services-file source
  // Windows' own resolver consults, and the one that answers for every
  // service the table above does not carry.  Case-insensitive per the API,
  // TCP only because every hook here tunnels a TCP connection.  The
  // servent it returns is owned by winsock and only s_port is read, from
  // this thread, immediately, so the shared buffer is of no concern.
  if (const auto *entry = getservbyname(servicename.c_str(), "tcp");
      entry != nullptr) {
    const auto port = ntohs(entry->s_port);
    if (port != 0) {
      return port;
    }
  }

  return std::nullopt;
}

inline std::optional<IpAddr> ipaddr_from_name(const std::string &nodename,
                                              const std::string &servicename) {
  auto port = service_to_port(servicename);
  if (!port) {
    return std::nullopt;
  }

  asio::error_code ec;
  if (auto addr = ip::make_address(nodename, ec); !ec) {
    return from_asio(addr, *port);
  } else {
    return IpAddr({}, {}, nodename, *port);
  }
}

inline std::optional<IpAddr> ipaddr_from_name(const std::wstring &nodename,
                                              const std::wstring &servicename) {

  return ipaddr_from_name(utf8_encode(nodename), utf8_encode(servicename));
}

template <auto F, pp::basic_fixed_string N>
struct hook_WSAConnectByName : minhook::api<F, hook_WSAConnectByName<F, N>> {
  using base = minhook::api<F, hook_WSAConnectByName<F, N>>;

  template <typename Char>
  static BOOL PASCAL detour(SOCKET s, Char *nodename, Char *servicename,
                            LPDWORD LocalAddressLength, LPSOCKADDR LocalAddress,
                            LPDWORD RemoteAddressLength,
                            LPSOCKADDR RemoteAddress,
                            const struct timeval *timeout,
                            LPWSAOVERLAPPED Reserved) {
    // Not a stream: straight through, refusal included -- the fail-closed
    // below is about not leaking a TCP connection, and a datagram socket
    // has no TCP connection to leak.
    if (!socket_is_stream(s)) {
      return base::original(s, nodename, servicename, LocalAddressLength,
                            LocalAddress, RemoteAddressLength, RemoteAddress,
                            timeout, Reserved);
    }

    if (config) {
      auto cfg = config->get();
      auto proxy = cfg["addr"_f];
      auto log = cfg["log"_f];

      // Neither pointer may be handed over unchecked: WSAConnectByName
      // validates them itself (measured on this SDK -- a NULL node or a NULL
      // service comes back FALSE with WSAEINVAL 10022 and connects to
      // nothing), and either one reaching ipaddr_from_name would build a
      // std::string out of nullptr, undefined behaviour sitting inside
      // someone else's process.  So the names are read only when both are
      // there; a missing one is simply "no endpoint", the same dead end as an
      // unresolvable service, which the refusal below already handles.
      auto addr = nodename && servicename
                      ? ipaddr_from_name(nodename, servicename)
                      : std::optional<IpAddr>{};

      // A service nobody could name is a dead end, not a licence to let the
      // original resolve it and connect: that is a direct, unproxied route out
      // of the capsule and the app would never know.  So this fails closed,
      // the P4 policy every other refusal in this file follows.  A name that
      // was never passed (NULL above) is refused the same way: with a proxy
      // configured, an endpoint this hook cannot name is not a reason to let
      // the operating system pick the destination -- the app gets a failed
      // connect either way, and the capsule keeps its word.  Without a proxy
      // there is nothing to route, so the original still answers, WSAEINVAL
      // and all.
      //
      // WSAConnectByName2 says of its return value: "If the function fails,
      // the return value is FALSE. To get extended error information, call
      // WSAGetLastError."  fail_proxied_connect supplies both halves -- FALSE
      // plus WSAECONNREFUSED (or the WSAETIMEDOUT already pending) -- the same
      // code a refused or unreachable proxy leaves behind, so a caller that
      // copes with one copes with both, and no new failure mode appears on a
      // path that used to silently succeed.
      if (!addr && proxy) {
        return fail_proxied_connect(s, FALSE);
      }

      if (addr) {
        if (queue && log && log.value()) {
          queue->push(create_message<InjecteeMessage, "connect">(
              InjecteeConnect{(std::uint32_t)s, addr, proxy, N}));
        }

        if (proxy) {
          if (auto [proxysa, addr_size] = to_sockaddr(*proxy); proxysa) {
            blocking_scope scope(s, SOCKS_HANDSHAKE_TIMEOUT_MS);

            auto ret = hook_connect::original(s, proxysa.get(), addr_size);
            if (ret)
              return ret;

            if (!socks5_handshake(s, socks5_credentials_from(cfg))) {
              return fail_proxied_connect(s, FALSE);
            }
            if (socks5_request(s, *addr) != SOCKS_SUCCESS) {
              return fail_proxied_connect(s, FALSE);
            }

            sockaddr peer;
            int peer_size = sizeof(peer);
            getsockname(s, &peer, &peer_size);

            *RemoteAddressLength =
                std::min(*RemoteAddressLength, (DWORD)peer_size);
            memcpy(RemoteAddress, &peer, *RemoteAddressLength);

            sockaddr local;
            int local_size = sizeof(local);
            getsockname(s, &local, &local_size);

            *LocalAddressLength =
                std::min(*LocalAddressLength, (DWORD)local_size);
            memcpy(LocalAddress, &local, *LocalAddressLength);

            return TRUE;
          }
        }
      }
    }

    return base::original(s, nodename, servicename, LocalAddressLength,
                          LocalAddress, RemoteAddressLength, RemoteAddress,
                          timeout, Reserved);
  }
};

struct hook_WSAConnectByNameA
    : hook_WSAConnectByName<WSAConnectByNameA, "WSAConnectByNameA"> {};
struct hook_WSAConnectByNameW
    : hook_WSAConnectByName<WSAConnectByNameW, "WSAConnectByNameW"> {};

template <typename Char> struct startup_info_ptr_impl;

template <>
struct startup_info_ptr_impl<char> : std::type_identity<LPSTARTUPINFOA> {};

template <>
struct startup_info_ptr_impl<wchar_t> : std::type_identity<LPSTARTUPINFOW> {};

template <typename Char>
using startup_info_ptr = typename startup_info_ptr_impl<Char>::type;

template <auto F>
struct hook_CreateProcess : minhook::api<F, hook_CreateProcess<F>> {
  using base = minhook::api<F, hook_CreateProcess<F>>;

  template <typename Char>
  static BOOL WINAPI detour(const Char *lpApplicationName, Char *lpCommandLine,
                            LPSECURITY_ATTRIBUTES lpProcessAttributes,
                            LPSECURITY_ATTRIBUTES lpThreadAttributes,
                            BOOL bInheritHandles, DWORD dwCreationFlags,
                            LPVOID lpEnvironment,
                            const Char *lpCurrentDirectory,
                            startup_info_ptr<Char> lpStartupInfo,
                            LPPROCESS_INFORMATION lpProcessInformation) {
    BOOL res = base::original(
        lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

    if (res && config) {
      auto cfg = config->get();
      auto subprocess = cfg["subprocess"_f];

      if (queue && subprocess && subprocess.value()) {
        queue->push(create_message<InjecteeMessage, "subpid">(
            lpProcessInformation->dwProcessId));
      }
    }

    return res;
  }
};

struct hook_CreateProcessA : hook_CreateProcess<CreateProcessA> {};
struct hook_CreateProcessW : hook_CreateProcess<CreateProcessW> {};

struct hook_ConnectEx {

  static inline LPFN_CONNECTEX ConnectEx = nullptr;

  // GetConnectEx() starts winsock to probe for the ConnectEx pointer;
  // remember that, so DLL_PROCESS_DETACH can balance it with WSACleanup
  static inline bool wsa_started = false;

  static LPFN_CONNECTEX GetConnectEx() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
      return nullptr;
    }
    wsa_started = true;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    DWORD numBytes = 0;
    GUID guid = WSAID_CONNECTEX;
    LPFN_CONNECTEX ConnectExPtr = nullptr;

    WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, (void *)&guid, sizeof(guid),
             (void *)&ConnectExPtr, sizeof(ConnectExPtr), &numBytes, nullptr,
             nullptr);

    closesocket(s);
    return ConnectExPtr;
  }

  static inline decltype(ConnectEx) original = nullptr;

  static BOOL PASCAL detour(SOCKET s, const struct sockaddr *name,
                            int namelen, PVOID lpSendBuffer,
                            DWORD dwSendDataLength, LPDWORD lpdwBytesSent,
                            LPOVERLAPPED lpOverlapped) {
    // Not a stream: straight through.  MSDN restricts ConnectEx to
    // SOCK_STREAM sockets anyway, so this costs nothing and keeps all four
    // routing sites saying the same thing first.
    if (!socket_is_stream(s)) {
      return original(s, name, namelen, lpSendBuffer, dwSendDataLength,
                      lpdwBytesSent, lpOverlapped);
    }

    if (is_inet(name) && config && !is_localhost(name)) {
      auto cfg = config->get();
      if (auto v = to_ip_addr(name)) {

        auto proxy = cfg["addr"_f];
        auto log = cfg["log"_f];
        if (queue && log && log.value()) {
          queue->push(create_message<InjecteeMessage, "connect">(
              InjecteeConnect{(std::uint32_t)s, *v, proxy, "ConnectEx"}));
        }

        if (proxy) {
          if (auto [addr, addr_size] = to_sockaddr(*proxy);
              addr && !sockequal(addr.get(), name)) {
            blocking_scope scope(s, SOCKS_HANDSHAKE_TIMEOUT_MS);

            auto ret = hook_connect::original(s, addr.get(), addr_size);
            if (ret)
              return ret;

            if (!socks5_handshake(s, socks5_credentials_from(cfg))) {
              return fail_proxied_connect(s, FALSE);
            }
            if (socks5_request(s, name) != SOCKS_SUCCESS) {
              return fail_proxied_connect(s, FALSE);
            }

            if (lpSendBuffer) {
              int len =
                  send(s, (const char *)lpSendBuffer, dwSendDataLength, 0);
              if (len == SOCKET_ERROR) {
                shutdown(s, SD_BOTH);
                return FALSE;
              }

              *lpdwBytesSent = len;
            }

            return TRUE;
          }
        }
      }
    }
    return original(s, name, namelen, lpSendBuffer, dwSendDataLength,
                    lpdwBytesSent, lpOverlapped);
  }

  static minhook::status create() {
    ConnectEx = GetConnectEx();
    return minhook::create(ConnectEx, detour, original);
  }

  static minhook::status remove() { return minhook::remove(ConnectEx); }
};

// balance the WSAStartup issued by hook_ConnectEx::GetConnectEx; call it
// from DLL_PROCESS_DETACH - a no-op unless we started winsock ourselves,
// so the host process's own winsock refcount is never touched
inline void hook_cleanup_wsa() {
  if (hook_ConnectEx::wsa_started) {
    hook_ConnectEx::wsa_started = false;
    WSACleanup();
  }
}

template <typename T, typename... Ts> minhook::status create_hooks() {
  if (auto status = T::create(); status.error()) {
    return status;
  }

  if constexpr (sizeof...(Ts) > 0) {
    if (auto status = create_hooks<Ts...>(); status.error()) {
      // partial failure: unroll - every already-created hook is removed
      // (deeper frames unrolled themselves before the error reached us)
      T::remove();
      return status;
    }
  }

  return MH_OK;
}

inline minhook::status hook_create_all() {
  return create_hooks<hook_connect, hook_WSAConnect, hook_WSAConnectByList,
                      hook_WSAConnectByNameA, hook_WSAConnectByNameW,
                      hook_CreateProcessA, hook_CreateProcessW,
                      hook_ioctlsocket, hook_WSAAsyncSelect,
                      hook_WSAEventSelect, hook_closesocket,
                      hook_ConnectEx>();
}

#endif
