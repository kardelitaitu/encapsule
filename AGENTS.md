# AGENTS.md — encapsule

Facts here were read from the cited sources (`master@8c0c6ed`). Re-verify after refactors.

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
  (`InjectorConfig` username=4 / password=5, the frozen P5 contract, :69-94) · `utils.hpp`
  process/wildcard/regex matching, `proxy_endpoint` + `parse_proxy_url` (:162-298) and the mapping
  name/token payload (:300-351) · `winraii.hpp` RAII handles, `virtual_memory`, `create_mapping` with
  explicit DACL (:142-200) · `async_io.hpp` length-prefixed message
  read/write · `queue.hpp` `blocking_queue<T>` · `minhook.hpp` CRTP MinHook
  wrapper · `version.hpp.in` → generated `version.hpp` (`:95`).
- `src/injectee/` — `encapsule-injectee.dll`, code that runs **inside the target process**:
  `injectee.cpp` (`DllMain` :88; detached client thread) · `hook.hpp` (winsock detours; it
  `#include`s `services.inc` from the service-name lookup — uncited on purpose, this file is being
  edited) · `services.inc` (service-name table, no guard) · `client.hpp` (IPC client,
  `injectee_config` :34-60, token hello :113-123) · `socks5.hpp` (pure builders :87-255 incl.
  `socks5_build_auth` :237-255; socket layer `socks5_handshake` :268-324 does the RFC 1929
  subnegotiation; single-TU include, see :257-261) · `winnet.hpp` (address helpers).
- `src/injector/` — code that runs **outside**, in the tool's own process: `injector.hpp` (mapping +
  `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`; DLL names at :190-191; token store :65-109) ·
  `server.hpp` (control server, `set_proxy_credentials`/`clear_proxy_credentials` :86-118, token check
  :217-229) · `injector_cli.{cpp,hpp}` (argparse+spdlog; `-p` parse + credential log :135-207) ·
  `injector_gui.{cpp,hpp}` (cycfi/elements) · `ui_elements/` (dynamic_list, text_box, tooltip widgets).
- `src/wow64/address_dumper.cpp` — Win32-only helper exe; returns the 32-bit `LoadLibraryW` address as
  its **process exit code** (`:22-26`); `#error`s if compiled as x64 (`:18-20`). Name unchanged by P3.
- `tests/` — host-side CTest suite: `schema/`, `utils/`, `winnet/`, `socks5/`, `queue/`, `e2e/`
  (+ `test_support.hpp`); the five unit dirs each hold one `add_executable(encapsule_test_<mod>)` +
  one `add_test`, `e2e/` additionally builds a decoy exe (`encapsule_e2e_dummy`, :19-27).

Entry points (3 `main` + 1 `DllMain`): `src/injector/injector_cli.cpp:111` (`encapsule-cli`),
`src/injector/injector_gui.cpp:41` (`encapsule`; window title `ce::app(..., "encapsule", "encapsule")` :45),
`src/wow64/address_dumper.cpp:22` (`wow64-address-dumper`), `src/injectee/injectee.cpp:88` `DllMain`.

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

- Registered tests: `common.schema`, `common.utils`, `injectee.winnet`, `injectee.socks5`,
  `common.queue` — one `add_test` per `tests/<mod>/CMakeLists.txt:4`, against targets renamed
  `encapsule_test_<mod>` (the pre-rebrand `proxinject_test_*` prefix is gone) — plus
  `e2e.loopback_selfcheck` and `e2e.inject_connect` (label `e2e`, `RUN_SERIAL`, `TIMEOUT 120`,
  `SKIP_RETURN_CODE 77`, `tests/e2e/CMakeLists.txt:52-53`). Test exes go to `build/<arch>/test_bin/`.
- `e2e.inject_connect` is a **real inject-and-connect** test (decoy process + in-process socks5 relay),
  registered only when `ENCAPSULE_E2E_INJECT` is ON (:58) **and** the build is 64-bit (:60); it is the
  CI e2e step's target.
- Auth coverage: `injectee.socks5` pins RFC 1929 **bytes** only (greeting shape + `socks5_build_auth`).
  The live accept/refuse walks run against a header-only relay (`tests/e2e/socks5_test_server.hpp`,
  `require_auth`) inside `e2e.loopback_selfcheck` (`e2e_test.cpp:674-682`); the inject-and-auth cases
  (`:869-902`, `--inject-auth`) exist but are NOT registered as a CTest yet (ROADMAP P5 last item).
- `BUILD_TESTING OFF CACHE BOOL "" FORCE` (`CMakeLists.txt:38`) silences only the *deps'* tests, not ours.

## 4. Codebase-memory index (use this for accurate tool calls)

Indexed as project **`C-dev-encapsule`** (name derived from path `C:\dev\encapsule`) — the project key is
**unchanged by the rebrand**. Root `C:/dev/encapsule`, branch `master`; `index_status` at this writing
reports 654 nodes / 1842 edges, 45 File nodes, 0 skipped, and packages `injector`/`common`/`injectee`/
`winnet`/`queue`/`utils`/`schema`/`test_support`/`wow64` (3 `main` entry points).

⚠️ **P5-era code may be missing — re-index (`mode=moderate`) before graph queries.** The index was rebuilt
after the P3 rename (the `tests/` tree is in it now, and the old "line numbers predate P3" warning is
obsolete), but `tests/socks5/` and `tests/e2e/` have no File nodes yet (`docs/` is excluded by design).
Live `parse_partial` list (5 files, ranges approximate): `build.ps1` (:9-10, :26-42),
`src/injectee/client.hpp` (:91), `src/injectee/hook.hpp` (:159, :271-273, :308, :389),
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
  message (`client.hpp:113-123`), the server refuses mismatches (`server.hpp:217-229`), and the mapping
  gets an explicit user+SYSTEM DACL, failing closed (`winraii.hpp:142-200`).
- Proxy credentials are **injector → injectee only**: parsed by `parse_proxy_url` (`utils.hpp:162-298`,
  `[user[:pass]@]host:port`), stored in `InjectorConfig` fields 4/5 (`server.hpp:86-118`), borrowed per
  connect by `socks5_credentials_from` (`socks5.hpp:80-85`). Report messages carry none
  (`schema.hpp:58-67`); the CLI logs the user name and the password *length*, never the secret
  (`injector_cli.cpp:201-206`); the GUI password box is unmasked (elements limitation,
  `injector_gui.hpp:319-322`).
- Two architectures in play: x64 injectee for 64-bit targets, Win32 `encapsule-injectee32.dll` +
  `wow64-address-dumper` for 32-bit targets under WoW64.

## 6. Conventions (observed in src/)

- 2-space indent, no tabs in `src/`; ~80-column clang-format style (8 lines in `injector.hpp`/`injector_gui.hpp` run to 82-109). `CMakeLists.txt`/`build.ps1` use tabs.
- Includes: `"quoted"` for same-package headers, `<angle>` for stdlib, third-party and `src/common`
  (on the include path, so `<utils.hpp>` and `"utils.hpp"` both appear).
- Header guards `ENCAPSULE_<PKG>_<NAME>` — all 17 `.hpp` headers under `src/` plus `version.hpp.in`
  (:16-17) use it; the last two stragglers (`injector.hpp`, `injector_gui.hpp`) are converted.
  `services.inc` has no guard by design (X-macro table included inside `hook.hpp`). No `#pragma once`
  anywhere.
- Every source file starts with the Apache-2.0 `// Copyright 2022 PragmaTwice` block (26/26 files);
  `ui_elements/` files additionally carry the upstream elements copyright. Attribution stays after the rebrand.
- snake_case for functions/variables and for `struct` names (`virtual_memory`, `get_port_mapping_name`);
  CRTP hook types are `hook_<winapi>`; aliases like `namespace ce = cycfi::elements`.
