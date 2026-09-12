# AGENTS.md — encapsule

Facts here were read from the cited sources (`master@a6c23c4`). Re-verify after refactors.
Line numbers are deliberately omitted for files other workers are editing right now (`hook.hpp`,
`injectee.cpp`, `udp_state.hpp`, `injector_cli.cpp`, `injector_gui.hpp`) — read those by symbol.

## 1. Project overview

**encapsule** (formerly `proxinject`; a fork of [PragmaTwice/proxinject](https://github.com/PragmaTwice/proxinject))
is a **Windows-only socks5 proxy injection tool**: it injects `encapsule-injectee.dll` into a running
process, redirects that process's outbound TCP connections through a user-supplied socks5 server —
authenticating to it with RFC 1929 username/password when credentials are configured — and reports
connections back to a GUI or CLI front end. Toolchain: MSVC + Windows SDK (winsock2), C++20,
CMake >= 3.20, driven by `build.ps1`. Third-party deps are FetchContent-pinned at configure time.

## 2. Repository layout

- `CMakeLists.txt` — all product targets: `encapsule_common` (INTERFACE, :97-99), `encapsule-injectee`
  (SHARED, :105-108), `encapsule` (GUI via elements: `ELEMENTS_APP_PROJECT` :118, icon :121-122,
  `include(ElementsConfigApp)` :126, target props :128-130), `encapsule-cli` (:136-139) and
  `wow64-address-dumper` (:142-144, built **only** in the injectee-only pass). Option
  `ENCAPSULE_INJECTEE_ONLY` (:20); version var `ENCAPSULE_VERSION` (:83-94) → `configure_file` (:95).
  No pre-rebrand target or ALIAS remains (P3 closed); the CTest gate is `ENCAPSULE_BUILD_TESTS` (:146)
  + `enable_testing()` (:147), and test targets are named `encapsule_test_*`. The only other CMake
  files are under `tests/`.
- `build.ps1` — build driver: configure + build Win32 and/or x64, then copy artifacts to `./release`.
- `CMakePresets.json` — presets `x64` / `win32-injectee-only` mirroring the two build.ps1 passes (no copy step).
- `setup.nsi` — NSIS installer; packs `release\*.*` (:56) into `encapsuleSetup.exe` (:18). The P3
  packaging straggler is **fixed**: `:10-11` define `NAME "encapsule"` / `APPFILE "encapsule.exe"`,
  i.e. exactly what `build.ps1` produces.
- `.github/workflows/build.yml` — CI: windows-2022, {Debug,Release} × {Win32,x64}; Build (:28),
  blocking `ctest` excluding e2e (:31), x64/Release e2e step with `--repeat until-pass:3` (:33-35).
- `resources/` — icon/png assets + `encapsule.rc` (GUI app icon, `CMakeLists.txt:121-122`).
- `docs/` — `BUILDING.md` (contributor build/debug guide) + logo and screenshot images.
- `.agents/ROADMAP.md` — roadmap + "fragile areas" notes (file:line references).
- `src/common/` — `encapsule_common`, header-only INTERFACE lib: `schema.hpp` protopuf IPC messages
  (`InjectorConfig` username=4 / password=5, the frozen P5 contract, :69-94; the 255-char credential
  caps are left to the front ends on purpose, :88-89) · `utils.hpp` process/wildcard/regex matching,
  `proxy_endpoint` + `parse_proxy_url` (:162-298; cap constant `proxy_credential_max_length` :206)
  and the mapping name/token payload (:300-351) · `winraii.hpp` RAII handles, `virtual_memory`,
  `create_mapping` with explicit DACL (:145-203), the tool-side helpers `enumerate_pids` /
  `process_watch_diff` / `process_short_name` (:284-339) and `create_process` (:341+) · `async_io.hpp`
  length-prefixed message read/write + `localhost` / `auto_endpoint` (:54 — port 0, so the control
  port is ephemeral per run) · `queue.hpp` `blocking_queue<T>` · `minhook.hpp` CRTP MinHook wrapper ·
  `version.hpp.in` → generated `version.hpp` (`:95`).
- `src/injectee/` — `encapsule-injectee.dll`, code that runs **inside the target process**:
  `injectee.cpp` (`DllMain`, the detached client thread, `get_ipc_payload()`; no line cites, in
  flight) · `hook.hpp` (winsock detours; `#include`s `services.inc` from the service-name lookup;
  no line cites, in flight) · `services.inc` (service-name table, no guard) · `client.hpp` (IPC
  client, `injectee_config` :34-60, token hello :113-123) · `socks5.hpp` — cited by symbol because the
  P7 UDP work is extending it right now: `socks5_credentials` + `socks5_credentials_from` borrow the
  login out of an `InjectorConfig`, the pure byte builders (`socks5_build_greeting`,
  `socks5_build_auth`, the two `socks5_request` shapes) sit above the socket layer, and
  `socks5_handshake` runs the greeting → method-choice → RFC 1929 state machine. Only the socket layer
  defines non-`inline` functions, so the header belongs in exactly one TU per binary ·
  `winnet.hpp` (address helpers).
  Two **pure, socket-free, host-testable** modules sit beside those and are **not** wired into the
  hooks yet: `fakeip.hpp` (guard `ENCAPSULE_INJECTEE_FAKEIP`) — the ROADMAP P6 fake-IP name table
  (T1+T2) over TEST-NET-2 / RFC 5737, nothing but `inline`/`constexpr`, no winsock and no
  `schema.hpp`, so unlike `socks5.hpp` it carries no single-TU trap; the socket-facing layer that
  feeds it real `sockaddr`/`IpAddr` values is still open. `udp_state.hpp` (guard
  `ENCAPSULE_INJECTEE_UDP_STATE`) — the ROADMAP P7a UDP association / per-socket state (caps, drop
  counters, recycled-`SOCKET` quarantine), sockets travel as `std::uintptr_t`, deliberately **not**
  thread-safe (one pump thread), and there is no pump and no `UDP ASSOCIATE` client yet.
- `src/injector/` — code that runs **outside**, in the tool's own process: `injector.hpp` (mapping +
  `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`; DLL names at :190-191; token store :65-109) ·
  `server.hpp` — cited by symbol, it is growing with P6/P7 too: the control server keeps
  `InjectorConfig` under `config_mutex`, `set_proxy_credentials` / `clear_proxy_credentials` push it
  to every session, `injectee_session::process()` refuses any hello whose token fails
  `injector::token_matches`, and `remove()` → `injector::forget_token` runs from `stop()` on every
  session loss · `injector_cli.{cpp,hpp}`
  (argparse+spdlog; `-p` parse, authority-only rejection message and the credential log line — no
  line cites, in flight) · `injector_gui.{cpp,hpp}` (cycfi/elements; username/password boxes with the
  255-char check — no line cites for the header, in flight) · `ui_elements/` (dynamic_list, text_box,
  tooltip widgets).
- `src/wow64/address_dumper.cpp` — Win32-only helper exe; returns the 32-bit `LoadLibraryW` address as
  its **process exit code** (`:22-26`); `#error`s if compiled as x64 (`:18-20`). Name unchanged by P3.
- `tests/` — host-side CTest suite: `schema/`, `utils/`, `winnet/`, `socks5/`, `queue/`, `fakeip/`,
  `udp/`, `e2e/` (+ `test_support.hpp`); the **seven** unit dirs each hold one
  `add_executable(encapsule_test_<mod>)` + one `add_test` (`tests/<mod>/CMakeLists.txt:4`), and
  `fakeip/` / `udp/` link nothing but the include path — that is the point of those two headers.
  `e2e/` additionally builds a decoy exe (`encapsule_e2e_dummy`, :19-27) and a header-only relay
  (`socks5_test_server.hpp`, `require_auth`); `tests/` is not added in the injectee-only pass.

Entry points (3 `main` + 1 `DllMain`): `main` in `src/injector/injector_cli.cpp` (`encapsule-cli`;
line uncited, in flight), `src/injector/injector_gui.cpp:41` (`encapsule`; window title
`ce::app(..., "encapsule", "encapsule")` :45), `src/wow64/address_dumper.cpp:22`
(`wow64-address-dumper`), and `DllMain` in `src/injectee/injectee.cpp` (uncited, in flight).

## 3. Build & verify

```powershell
./build.ps1 -mode Release -arch x64     # documented build command (README, build.yml:28)
```

Params (`build.ps1:1-7`): `-build_dir` (`build`), `-release_dir` (`release`), `-mode` (`Release`),
`-arch` (`x64`), `-skip_cmake` switch. Verified semantics:

- `-arch` accepts **exactly** `Win32` or `x64`; anything else exits 1 (`build.ps1:13-16`). `x86`/`amd64` invalid.
- `-arch x64` runs **two** passes: full x64 configure (`:26`) plus a Win32 configure with
  `-DENCAPSULE_INJECTEE_ONLY=ON` (`:20,28`) so only the 32-bit injectee is built there.
- `-arch Win32` runs the single Win32 pass with all targets. Compile: `cmake --build <dir> --config $mode -j` (`:32,34`).
- Artifacts land in `./release` (`:36-38`): `encapsule.exe`, `encapsule-cli.exe`,
  `encapsule-injectee.dll`; an x64 run also copies `encapsule-injectee32.dll` + `wow64-address-dumper.exe`
  (`:41-42`), and `LICENSE` is copied too (`:45`). Optional installer:
  `makensis /DVERSION=$(git describe --tags) setup.nsi` — `setup.nsi` now names the built `encapsule.exe`.
- **CMake 4.x:** every configure carries `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` (`build.ps1:26,28`, since
  d724762; also `CMakePresets.json:29`) because the FetchContent deps declare older minimums — keep it on
  any hand-rolled `cmake` configure line.
- **Version:** configure reads `git describe --tags`; on failure it warns and falls back to
  `v0.0.0-unknown` (`CMakeLists.txt:83-92`), so a tag-less clone configures fine — no workaround needed.

**Tests: host-side CTest suite; the unit tests need no injection.** On by default (`CMakeLists.txt:146-150`);
skipped under `ENCAPSULE_INJECTEE_ONLY=ON`, so the Win32 pass of an x64 run registers no tests. Run after building:

```powershell
cmake --build build/x64 --config Release -j $env:NUMBER_OF_PROCESSORS   # or: cmake --build --preset x64
ctest --test-dir build/x64 -C Release --output-on-failure -E '^e2e\.'   # CI blocking step, build.yml:31
```

- Registered tests — **10 on an x64 build, 8 on a Win32 one**. Seven unit: `common.schema`,
  `common.utils`, `common.queue`, `injectee.winnet`, `injectee.socks5`, `injectee.fakeip`,
  `injectee.udp` (one `add_test` each at `tests/<mod>/CMakeLists.txt:4`, targets `encapsule_test_<mod>`).
  Three e2e, all labelled `e2e` with `RUN_SERIAL`, `TIMEOUT 120`, `SKIP_RETURN_CODE 77`
  (`tests/e2e/CMakeLists.txt:52-53`): `e2e.loopback_selfcheck` (always registered), plus
  `e2e.inject_connect` and `e2e.inject_auth`, both behind `ENCAPSULE_E2E_INJECT` (:58) **and** 64-bit
  (:60-81). Test exes go to `build/<arch>/test_bin/`.
- CI runs the same split: the blocking step is `ctest -E '^e2e\.'` (the seven unit tests, all four
  matrix legs), and the x64/Release-only step is `ctest -R '^e2e\.' --repeat until-pass:3`, which now
  covers **all three** e2e tests including the RFC 1929 one (`build.yml:30-35`).
- Auth coverage, by layer: `injectee.socks5` pins the RFC 1929 **bytes** only (greeting shape +
  `socks5_build_auth`); the live accept/refuse walks run against the header-only relay
  (`tests/e2e/socks5_test_server.hpp`, `require_auth`) inside `e2e.loopback_selfcheck`; and
  **`e2e.inject_auth` is registered** — real injection plus a proxy that demands credentials, one
  accepted case and one refused case that must fail closed (`tests/e2e/CMakeLists.txt:69-80`).
- Measured on a clean tree at `a6c23c4`, not inherited: the x64 suite ran **10/10 green** locally
  (~99 s total, `e2e.inject_auth` ~62 s of it). The only compile errors anywhere in the project are
  inside the `string_view.hpp` vendored by cycfi/elements (`nonstd/string_view.hpp:120`, C2143/C2447
  under MSVC 17.14) — that is why the **GUI target is CI-built only**; the injectee, the CLI, the
  dumper and every test build and run locally.
- `BUILD_TESTING OFF CACHE BOOL "" FORCE` (`CMakeLists.txt:38`) silences only the *deps'* tests, not ours.

## 4. Codebase-memory index (use this for accurate tool calls)

Indexed as project **`C-dev-encapsule`** (name derived from path `C:\dev\encapsule`) — the project key is
**unchanged by the rebrand**. Root `C:/dev/encapsule`, branch `master`; `index_status` at this writing
reports **732 nodes / 2214 edges**, 47 File nodes, 0 skipped, and packages `injector`/`common`/
`injectee`/`winnet`/`queue`/`utils`/`schema`/`test_support`/`wow64` (3 `main` entry points).

⚠️ **P6/P7-era code may be missing — re-index (`mode=moderate`) before graph queries.** The tree is in
(it has `tests/socks5/` now), but `src/injectee/fakeip.hpp`, `src/injectee/udp_state.hpp`,
`tests/fakeip/`, `tests/udp/` and `tests/e2e/` have **no File nodes**, and `docs/` is excluded by design.
Live `parse_partial` (5 files, ranges approximate and drifting while `hook.hpp` is edited): `build.ps1`,
`src/injectee/client.hpp` (:91), `src/injectee/hook.hpp` (:159, :271-273, :358, :473),
`src/injectee/services.inc` (whole file, :1-292), `src/injector/injector.hpp` (:149). Use `grep`/`read`
as fallback in those files.

Re-index: `mcp cbm index_repository(repo_path="C:\dev\encapsule", mode="moderate")`. Prefer
`search_graph` / `trace_path` / `get_code_snippet` over bulk reading; `detect_changes({})` for blast radius.

## 5. Environment notes

- Windows host, PowerShell for the build wrapper; needs MSVC + Windows SDK discoverable by CMake
  (`build.ps1` shells out to `cmake` only; the VS generator locates MSBuild). `cmake` must be on PATH.
- C++20 (`CMakeLists.txt:26`), static CRT `MultiThreaded`/`MultiThreadedDebug` (`:28`),
  `_WIN32_WINNT=0x0A00` + `UNICODE` (`:81,99`). Static CRT is required because the DLL loads into foreign processes.
- **Injected vs. injector code:** `src/injectee/` executes inside a *foreign* process (hooks live winsock
  APIs; a crash kills the target; `DllMain` must not block; the module stays resident by design).
  `src/injector/` executes in the tool's own process. `src/common/` is compiled into **both** — check both
  sides before changing `schema.hpp` (protopuf wire format), the mapping name/payload (`utils.hpp:300-351`)
  or the `encapsule-injectee*.dll` lookup names (`injector.hpp:190-191`).
- IPC is authenticated: the mapping carries port + 8-byte per-injection token (`utils.hpp:306-329`,
  built fail-closed by `get_port_mapping_payload`, :334-351), the injectee re-presents it in every
  message (`client.hpp:113-123`), the server refuses mismatches (`server.hpp`, `injectee_session::process`), and the mapping
  gets an explicit user+SYSTEM DACL, failing closed (`winraii.hpp:145-203`).
- Proxy credentials are **injector → injectee only**: parsed by `parse_proxy_url` (`utils.hpp:162-298`,
  `[user[:pass]@]host:port`, 255-char cap per field via `proxy_credential_max_length`), stored in
  `InjectorConfig` fields 4/5 (`server.hpp`, `set_proxy_credentials`), borrowed per connect by
  `socks5_credentials_from` (`socks5.hpp`); report messages carry none (`schema.hpp:58-67`) and an unset field adds zero
  bytes, so a credential-free config is byte-identical to pre-P5.
- Front-end credential handling, as read off the current tree (both files are in flight, so symbols
  not lines): **neither front end trims the password** — the CLI passes `-p` through untrimmed, the
  GUI reads its password box raw; the GUI *does* trim host, port and **username**, so a leading space
  in a username is invisible from the GUI but literal from the CLI — and it is the **socks5 server**
  that turns such a login down; encapsule's own front end never inspects a credential. The GUI
  enforces the 255-char cap on both fields and, when they are over-long, pops its proxy toggle back
  off and writes the reason into its log box. The CLI's cap is the same one: `parse_proxy_url`
  refuses either field past it, and a rejected `-p` is a hard exit-2 error that names only the
  authority after the last `@` (a non-numeric host is refused there too — only dotted IPv4/IPv6 is
  accepted). The CLI logs the user name plus the password *length* and nothing more; the GUI's
  password box is **not masked** (elements has no password box) and holds credentials in memory
  only.
- One credential exposure stays OPEN and is documented in `docs/BUILDING.md`: the CLI's endpoint is
  an argument, so a `-p user:pass@host:port` sits in argv where same-user processes and Sysmon EID 1
  can read it (the GUI's separate boxes keep it out of argv). The error paths are closed: a rejected `-p`
  names only the authority after the last `@`, and argparse's `"Unknown argument: " + token` echo is
  run through `sanitize_parse_error`/`scrub_token` in `injector_cli.cpp` (no line cites, in flight),
  which drops everything up to and including that last `@` — so a mistyped
  `-palice:pw@1.2.3.4:1080` prints `1.2.3.4:1080`, and a proxy-flag token holding nothing but the
  secret is dropped whole (`"Invalid argument (value redacted)"`).
- Two architectures in play: x64 injectee for 64-bit targets, Win32 `encapsule-injectee32.dll` +
  `wow64-address-dumper` for 32-bit targets under WoW64.

## 6. Conventions (observed in src/)

- 2-space indent, no tabs in `src/`; ~80-column clang-format style — re-measured on the current
  tree, exactly **1** line of `src/` runs past 80 columns (`injector.hpp:191`, 82 chars); the
  longest line in `injector_gui.hpp` and `fakeip.hpp` is 80. `CMakeLists.txt`/`build.ps1` use tabs.
- Includes: `"quoted"` for same-package headers, `<angle>` for stdlib, third-party and `src/common`
  (on the include path, so `<utils.hpp>` and `"utils.hpp"` both appear).
- Header guards `ENCAPSULE_<PKG>_<NAME>` — all **19** `.hpp` headers under `src/` (now including
  `fakeip.hpp` → `ENCAPSULE_INJECTEE_FAKEIP`, `udp_state.hpp` → `ENCAPSULE_INJECTEE_UDP_STATE`) plus
  `version.hpp.in` use it; no stragglers. `services.inc` has no guard by design (X-macro table
  included inside `hook.hpp`). No `#pragma once` anywhere.
- Every source file starts with the Apache-2.0 `// Copyright 2022 PragmaTwice` block (**28/28** files
  under `src/`); `ui_elements/` files additionally carry the upstream elements copyright. Attribution
  stays after the rebrand.
- snake_case for functions/variables and for `struct` names (`virtual_memory`, `get_port_mapping_name`);
  CRTP hook types are `hook_<winapi>`; aliases like `namespace ce = cycfi::elements`.
