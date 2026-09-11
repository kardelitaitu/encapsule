# proxinject — ROADMAP

> Living document for contributors and AI agents working in this repository.
> Grounded in the verified state of `master@b4b29ee`; file/line references included.
> Tick checkboxes as items land, and re-verify line numbers after refactors.

## 1. Where the project stands

proxinject is a **Windows-only socks5 proxy injection tool**: it injects `proxinjectee.dll`
into a running process and redirects that process's outbound TCP connections through a
user-supplied socks5 server. One codebase, four real build targets
(CMake ≥ 3.20, C++20, MSVC only, static CRT):

| Target | Type | Sources | Role |
|---|---|---|---|
| `proxinject_common` | INTERFACE (header-only) | `src/common` | IPC schema, RAII, process matching, MinHook CRTP wrapper |
| `proxinjectee` | SHARED DLL | `src/injectee` | hooks winsock, runs socks5 client, IPC client |
| `proxinjector` | GUI exe | `src/injector/injector_gui.cpp`, `src/injector/ui_elements` | cycfi/elements UI: process list (`dynamic_list`), connection log |
| `proxinjector-cli` | exe | `src/injector/injector_cli.cpp` | argparse CLI, spdlog logging |
| `wow64-address-dumper` | Win32 exe (only with `PROXINJECTEE_ONLY=ON`) | `src/wow64` | returns 32-bit `LoadLibraryW` address as its exit code (WoW64 pivot) |

Runtime flow (verified by reading source): injector binds an ephemeral `127.0.0.1:0`
control server → `CreateFileMappingW("PROXINJECT_PORT_IPC_<pid>")` carries the port
(`src/common/utils.hpp:156`) → `VirtualAllocEx` + `WriteProcessMemory` +
`CreateRemoteThread(LoadLibraryW)` injects the DLL → injectee installs MinHook detours
(`connect`, `WSAConnect*`, `WSAConnectByName*`, `ConnectEx`, `CreateProcessA/W`,
`ioctlsocket`, `WSAAsyncSelect`, `WSAEventSelect`) → connects back → receives
`InjectorConfig` → hooks redirect AF_INET non-localhost connects to the socks5 server
(no-auth handshake only) and report connections over protopuf, length-prefixed TCP IPC.
Child processes are recursively injected via the `CreateProcess` hooks + `subpid` messages.

Dependencies are all FetchContent, pinned: minhook@49d03ad, protopuf v2.2.1,
argparse v2.9, spdlog v1.10.0, asio-1-22-2 (header-only populate), and a patched
cycfi/elements fork (`PragmaTwice/elements@8e4dfff`, recursive submodules).

Recent activity (git log): `dynamic_list` scaling/stretching, millisecond log
timestamps, wildcard/regexp process matching, refactors into `winraii.hpp`,
UI data-race fixes (`view.post`).

## 2. Fragile areas — read before touching

| Area | Files | Why fragile |
|---|---|---|
| Hook detours & MinHook wrapper | `src/common/minhook.hpp`, `src/injectee/hook.hpp` | detour signatures must match exactly; `hook_ConnectEx` bypasses the CRTP template because the function pointer comes from `WSAIoctl(WSAID_CONNECTEX)` |
| Non-blocking socket handling | `hook.hpp` (`blocking_scope`, `nbio_map`) | handshake temporarily forces blocking mode; state is remembered/restored via the `ioctlsocket`/`WSA*Select` hooks |
| DLL self-unload | `src/injectee/injectee.cpp` | detached thread `FreeLibrary`s the DLL itself — never join it or hold references past exit |
| WoW64 pivot | `src/injector/injector.hpp:33`, `src/wow64/address_dumper.cpp` | 32-bit `LoadLibraryW` address travels as a process exit code |
| ODR gamble | `src/common/winraii.hpp` | non-`inline` free functions in a header; safe only while each exe has a single TU including it |
| IPv6 byte order | `to_ip_addr` / `to_sockaddr` in `src/injectee/winnet.hpp` | byte order is surprising (reported as reversed); verify before "fixing" |
| IPC trust model | `src/injector/server.hpp`, `src/common/utils.hpp:156` | no authentication; the IPC port travels through a named file mapping that any same-user process can read or race |

## 3. Roadmap

### P0 — Correctness & safety (do first)
- [ ] Fix the only in-code FIXME: address-family equality in `src/injectee/winnet.hpp:98`.
- [ ] Audit the `blocking_scope` path for stalls: a socks5 server that never answers
      blocks an application thread indefinitely. Add a timeout and decide the fallback
      (fail the connect vs. direct connect).
- [ ] Harden local IPC: authenticate injectee↔injector sessions (e.g. per-injection
      token stored in the mapping) and restrict the mapping's DACL; today any same-user
      process can read the port or connect to the control server.
- [ ] Define injectee behavior on injector exit mid-session (reconnect policy, clean
      unload) and on partial injection failure; document it.

### P1 — Protocol & proxy coverage
- [ ] Hook DNS resolution (`getaddrinfo`, `GetAddrInfoW`, `GetAddrInfoExW`) — currently
      absent (grep-verified), so hostnames still resolve outside the tunnel: DNS leaks
      and connections can break on DNS-blocked hosts.
- [ ] SOCKS5 username/password auth (RFC 1929); the handshake hardcodes no-auth
      `{5,1,0}` in `src/injectee/socks5.hpp`.
- [ ] State the UDP story explicitly: hooks cover TCP connect paths only; either
      document TCP-only scope in the README or implement UDP ASSOCIATE.
- [ ] Focused tests around `to_sockaddr` / `to_ip_addr` for IPv4/IPv6/domain
      (see the IPv6 byte-order note above).

### P2 — Testing & CI (none exists today; `**/*test*` is empty)
- [ ] First host-side test target (no injection needed): round-trip `schema.hpp`
      protopuf messages, `utils.hpp` wildcard/regex matching, `queue.hpp` behavior,
      socks5 request byte builders.
- [ ] Wire CTest into `.github/workflows/build.yml` (existing job: windows-2022 with a
      {Debug, Release} × {Win32, x64} matrix; snapshot/installer artifacts; gh-release
      on `v*` tags).
- [ ] End-to-end smoke harness: spawn a dummy target process and an in-process socks5
      server, inject, assert the connection arrives through the proxy.

### P3 — Build & packaging hygiene
- [ ] Replace `file(GLOB)` source collection (`CMakeLists.txt:98,106,122`) with explicit
      lists or add `CONFIGURE_DEPENDS`.
- [ ] `git describe` hard-fails configuration outside a git checkout
      (`CMakeLists.txt:82-89`) — add a fallback version string.
- [ ] Add CMake presets mirroring `build.ps1` (x64 full build + Win32
      `PROXINJECTEE_ONLY=ON` pass that yields `proxinjectee32.dll`).
- [ ] Scheduled chore: bump pinned deps (asio 1.22.2, spdlog 1.10.0, argparse v2.9,
      protopuf v2.2.1) and refresh the elements fork pin.
- [ ] Contributor docs: build prerequisites (MSVC, Windows SDK, CMake), debugging tips
      for injected processes; `docs/` holds only image assets and the logo attribution
      (`docs/logo/attribute.md`).

### P4 — Product / UX
- [ ] GUI/CLI parity is nearly complete (verified in `make_controls`): the GUI already
      offers all six input modes (pid, name, name-regexp, path, path-regexp, exec) and
      proxy/log/subprocess toggles. Remaining gap: the CLI-only
      `-w/--new-console-window` for exec mode — surface it as a GUI toggle.
- [ ] Auto-inject on process start: the matching utilities (`match_process*` in
      `src/common/winraii.hpp`) already support wildcard/regexp — a process-watch loop
      can reuse them.
- [ ] Connection-log improvements: per-process aggregation, copy/export of the log.
- [ ] Tray icon / minimize behavior; continued `dynamic_list` polish (the active area
      of recent commits).

## 4. Non-goals

- Cross-platform support: winsock assumptions and Windows-only guards are intentional
  (`CMakeLists.txt` fails fast on non-WIN32).
- Switching UI toolkit, hook engine (MinHook), or serialization (protopuf).
- Dynamic CRT linkage (`MultiThreaded` static runtime is deliberate for injection).

## 5. Verification recipe (for agents)

1. Build: `./build.ps1 -mode Release -arch x64` — requires MSVC + Windows SDK; builds
   x64 plus the Win32 injectee pass and assembles `./release` (incl.
   `proxinjectee32.dll`, `wow64-address-dumper.exe`).
2. There is no test suite yet — at minimum run
   `proxinjector-cli -p <host:port> -i <pid> -l` against a local socks5 server and a
   target process, and confirm the redirected connections in the log.
3. Check `git log --oneline` for the area you are touching; several files
   (`winraii.hpp`, `dynamic_list`) are mid-refactor territory.
