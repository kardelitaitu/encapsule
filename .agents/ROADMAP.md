# encapsule — ROADMAP

> Living document for contributors and AI agents working in this repository.
> Grounded in the verified state of `master@ede7e02`; file/line references included.
> Tick checkboxes as items land, and re-verify line numbers after refactors.
>
> Rebrand note: P3 LANDED — the tree is now branded `encapsule` (old names survive only
> in this document's historical task text, the README fork-attribution, and legal lines).

## 1. Where the project stands

**encapsule** (formerly `proxinject`; fork of PragmaTwice/proxinject) is a **Windows-only socks5 proxy injection tool**: it injects `proxinjectee.dll`
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

> Sequencing rationale: foundations first (reproducible builds, then a test/CI safety
> net) so every later change is verifiable → mechanical rebrand before feature work so
> new code lands under final names → correctness/hardening → protocol features in
> increasing size (auth → DNS → UDP) → UX polish last.

### P1 — Build & packaging foundation (quick wins)
- [x] Replace `file(GLOB)` source collection with explicit source lists (or add
      `CONFIGURE_DEPENDS`) at `CMakeLists.txt:98,106,122`.
- [x] Add a fallback version string when `git describe` fails outside a git checkout
      (`CMakeLists.txt:82-89`) instead of hard-failing configuration.
- [x] Add `CMakePresets.json` mirroring `build.ps1` (x64 full build + Win32
      `PROXINJECTEE_ONLY=ON` pass that yields `proxinjectee32.dll`).
- [ ] Scheduled chore: bump pinned FetchContent deps (asio 1.22.2, spdlog 1.10.0,
      argparse v2.9, protopuf v2.2.1) and refresh the elements fork pin.
- [x] Add contributor docs: build prerequisites (MSVC, Windows SDK, CMake) and
      debugging tips for injected processes (`docs/` currently holds only image assets
      and the logo attribution, `docs/logo/attribute.md`).

### P2 — Testing & CI foundation (none exists today; `**/*test*` is empty)
- [x] Create a CTest-enabled host-side test target (no injection needed).
- [x] Round-trip tests for `schema.hpp` protopuf messages (encode/decode).
- [x] Tests for `utils.hpp` wildcard/regex process matching.
- [x] Tests for `to_sockaddr` / `to_ip_addr` IPv4/IPv6/domain conversions (locks down
      the byte-order question flagged in §2).
- [x] Tests for socks5 request byte builders and `queue.hpp` behavior. (queue: cfb7622;
      builders: 410a54e P5-S1 seam — pure inline builders, 17 byte-pinned cases incl.
      the IpAddr-overload wire fix (LIVE path hook.hpp:336 WSAConnectByName) and the
      SOCKS_REQUEST_MAX_SIZE stack-overrun fix.)
- [x] Wire CTest into `.github/workflows/build.yml` (existing job: windows-2022 with a
      {Debug, Release} × {Win32, x64} matrix; snapshot/installer artifacts; gh-release
      on `v*` tags).
- [x] End-to-end smoke harness: spawn a dummy target process and an in-process socks5
      server, inject, assert the connection arrives through the proxy.
      (CI gate: blocking again with `--repeat until-pass:3` — 6bd44e7 lifts the
      9445dd4 `continue-on-error` quarantine now that the injection leg is real.
      Optional polish: fold `e2e.*` back into the single `Test` step and add
      `--error-on-skip`.)

### P3 — Rebrand `proxinject` → `encapsule` (owner-approved)
- [x] Decide final names: GUI exe `encapsule`, CLI `encapsule-cli`, injectee
      `encapsule-injectee.dll` / `encapsule-injectee32.dll` (or mirror the old
      `proxinjectee` naming); keep `wow64-address-dumper` unless decided otherwise.
- [x] CMake: `project()` name, target names, `ELEMENTS_APP_PROJECT`, and the
      `PROXINJECT_VERSION` / `version.hpp.in` variable set (`CMakeLists.txt`).
- [x] Rename the IPC mapping prefix `ENCAPSULE_PORT_IPC_<pid>` on BOTH injector and
      injectee sides atomically (`src/common/utils.hpp:156` + the injectee lookup).
- [x] Update `find_injectee` DLL lookup (`src/injector/injector.hpp`) and the
      `build.ps1` Win32 copy step (proxinjectee.dll → *32.dll).
- [x] Update UI/CLI strings: `ce::app(...)` window title now `encapsule`
      (`src/injector/injector_gui.cpp`), CLI description/help text
      (`src/injector/injector_cli.cpp`).
- [x] Update packaging: `setup.nsi` product/shortcut names,
      `.github/workflows/build.yml` artifact/release names (`proxinject-snapshot-*`),
      `resources/proxinject.rc` and logo assets.
- [x] Update docs/meta: README title, badges, screenshots done (owner); repo description + winget manifest remain owner-domain
      already points at `kardelitaitu/encapsule.git`); decide whether to publish a
      `kardelitaitu.encapsule` winget manifest (upstream's package stays theirs).
- [x] Full rebuild (x64 + Win32) and end-to-end smoke test: inject into a real process
      and confirm the proxy path still works after the rename. (Gate: build.ps1 exit 0
      both passes, ctest 6/6 incl. e2e.inject_connect through renamed mapping+DLLs.)

### P4 — Correctness & hardening
- [x] Fix the only in-code FIXME: address-family equality in
      `src/injectee/winnet.hpp:98`.
- [x] Add a timeout to the `blocking_scope` socks5 handshake path — a server that
      never answers must not block an application thread indefinitely; decide the
      fallback (fail the connect vs. direct connect). (77d60e8: SO_RCVTIMEO/SNDTIMEO
      deadline 3000ms all 4 detour sites, restore-not-clobber, fail-closed fallback
      per owner decision; nbio_map race + growth fixed. Proxy-connect bound = W7 hardening.)
- [x] Authenticate injectee↔injector sessions: per-injection token stored in the port
      mapping and verified by the control server. (78b919b contract + 22e6d7c flow:
      token minted fail-closed, registered before CreateRemoteThread, verified at
      introduction, mismatch = session refused; mutation-probe proven; DoS on
      unregistered connect fixed. Per-message auth = available follow-up.)
- [x] Restrict the named mapping's DACL so same-user processes can't read the IPC
      port or race the mapping name (`src/common/utils.hpp:156`). (e1f4d00: SDDL
      user+SYSTEM, fail-closed on any SD failure; cross-user targets now fail
      cleanly via the W2 fail-safe — same-user injection proven by e2e.inject_connect.)
- [x] Define and implement injector-exit behavior mid-session: reconnect policy and
      clean DLL unload; document it. (4a37adc: stay-resident, bounded 1s-10s backoff
      re-presenting the token, fail-closed routing via pinned config, docs §3;
      manual kill-probe: routing 3ms post-kill, reconnect at 1.006s, per-injection
      token randomness verified. Follow-up: e2e.inject_kill_reconnect case.)
- [x] Audit partial injection failure: mapping cleanup and no half-initialized hooks
      left in the target process. (256e27d fail-safe mapping + verified load result;
      41369fd reverse-order hook unroll + DllMain never live half-initialized + WSA refcount guard.)

### P5 — Feature: proxy username + password (owner-approved; RFC 1929)
- [x] Extend `InjectorConfig` (`src/common/schema.hpp`) with credential fields; both
      sides move together to keep the protopuf wire format compatible. (e7ff326:
      username=4/password=5 optional+separate; credential-free config pinned
      byte-identical to pre-P5 wire; report messages pinned credential-free.)
- [x] Injectee: offer methods `{5, 2, 0}` (no-auth + userpass, method 2 preferred)
      when credentials are configured — `{5,1,0}` byte-identical otherwise
      (a76f052: offer tracks credential state; `enabled()` is OR, blank password ok).
- [x] Injectee: implement the RFC 1929 user/pass subnegotiation and apply configured
      credentials during `socks5_handshake` (a76f052: socks5_build_auth pinned bytes,
      required creds param at all 4 hook sites — compiler-enforced, no dangling-view
      trap via socks5_credentials_from(cfg), fail-closed on 0xFF/short/bad-status,
      no silent unauthenticated fallback).
- [x] Server side: validate and forward credentials from the frontends into the
      config message (41e2d2e: injector_server::set_proxy_credentials/
      clear_proxy_credentials under config_mutex + broadcast_config; optional engaged
      -> set, nullopt -> field stays ABSENT (never ""), clear re-broadcasts a
      byte-identical credential-free config).
- [x] CLI: accept credentials via `-p [user[:pass]@]host:port` (41e2d2e: shared pure
      parse_proxy_url — last-@ / first-: / bracketed-IPv6 / 255 caps; embedded form
      chosen over flags; empty username => no creds; hostname now exit 2 instead of
      std::terminate; password never logged, `-p` help updated).
- [x] GUI: accept credentials in the proxy input (41de274: dedicated username/password
      boxes + no-mask tooltip; CI-compiled — local elements/MSVC exception).
- [x] Unit tests: handshake byte-level tests covering auth success and auth failure
      (a76f052 builders/offer 25 cases + 18ef7c4 live-socket relay walk: accept, bad
      pass refused, demanded-without-creds -> {5,FF}, not-required -> {5,00} as
      today; + malformed 1929 refusals, relay stays live (7235543); tunnel proven
      post-negotiation; creds never logged).
- [ ] E2E: verify against a socks5 server that requires authentication.
      (harness + e2e.inject_auth landed ea12f75; RED pending the fix of a REAL
      fail-open bug it caught: creds-bearing InjectorConfig never applies, traffic
      goes direct. Push held until green.)

### P6 — Feature: DNS resolution hooking
- [ ] Decide the strategy: fake-IP domain mapping vs. pass-through resolution with
      remote resolve at the proxy (`ATYP=3` domain requests already exist in
      `socks5_request`).
- [ ] Hook `getaddrinfo` / `GetAddrInfoW` (+ `GetAddrInfoExW` if async resolution
      needs it) via the CRTP MinHook wrapper — currently absent (grep-verified), so
      DNS leaks outside the tunnel.
- [ ] Implement the chosen strategy in the injectee.
- [ ] Preserve async semantics for overlapped resolution paths (interplay with the
      existing `WSAAsyncSelect`/`WSAEventSelect` hooks).
- [ ] Emit DNS events into the existing connection-log pipeline.
- [ ] Tests: mapping-table unit tests; E2E check that no DNS query leaves the tunnel.

### P7 — Feature: UDP support (owner-approved)
- [ ] Survey the datagram API surface to hook: `sendto`, `WSASendTo`, `recvfrom`,
      `WSARecvFrom`, plus connected-UDP `send`/`recv` on `SOCK_DGRAM` sockets.
- [ ] Implement the SOCKS5 UDP ASSOCIATE client (RFC 1928 §7): TCP control request,
      relay endpoint reply, datagram header (FRAG/ATYP/addr/port).
- [ ] Decide the local-relay architecture (per-socket relay vs. shared relay socket).
- [ ] Hook outbound datagrams: encapsulate and forward via the relay.
- [ ] Hook inbound datagrams: decapsulate replies and hand them to the application.
- [ ] Handle exclusions: localhost targets and proxy-loop prevention for the relay
      traffic itself.
- [ ] Report UDP activity through the existing log pipeline.
- [ ] E2E test against a UDP-capable socks5 server; keep the TCP path regression-free.

### P8 — Product / UX
- [ ] Surface the CLI-only `-w/--new-console-window` as a GUI toggle (the last
      GUI/CLI parity gap; the GUI already covers all six input modes and
      proxy/log/subprocess toggles per `make_controls`).
- [ ] Auto-inject on process start: a watch loop reusing the `match_process*`
      utilities (`src/common/winraii.hpp`, wildcard/regexp already supported).
- [ ] Connection-log improvements: per-process aggregation, copy/export of the log.
- [ ] Tray icon / minimize behavior.
- [ ] Continued `dynamic_list` polish (the active area of recent commits).
- [ ] Refresh the README feature list once auth/DNS/UDP land.

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
   target process, and confirm the redirected connections in the log. (Binary names
   are per the current branding; the P3 rebrand renames them.)
3. Check `git log --oneline` for the area you are touching; several files
   (`winraii.hpp`, `dynamic_list`) are mid-refactor territory.
