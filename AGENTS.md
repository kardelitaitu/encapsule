# AGENTS.md — encapsule

Facts here were read from the cited sources (`master@94e5151`). Re-verify after refactors.

## 1. Project overview

**encapsule** (formerly `proxinject`; a fork of [PragmaTwice/proxinject](https://github.com/PragmaTwice/proxinject))
is a **Windows-only socks5 proxy injection tool**: it injects `encapsule-injectee.dll` into a running
process, redirects that process's outbound TCP connections through a user-supplied socks5 server, and
reports connections back to a GUI or CLI front end. Toolchain: MSVC + Windows SDK (winsock2), C++20,
CMake >= 3.20, driven by `build.ps1`. Third-party deps are FetchContent-pinned at configure time.

## 2. Repository layout

- `CMakeLists.txt` — all product targets: `encapsule_common` (INTERFACE, :97-99), `encapsule-injectee`
  (SHARED, :110), `encapsule` (GUI via elements, :123-135), `encapsule-cli` (:141), `wow64-address-dumper`
  (:148). Option `ENCAPSULE_INJECTEE_ONLY` (:20); version var `ENCAPSULE_VERSION` (:86-94). A temporary
  old-name ALIAS (:101-104) keeps `tests/` linking; the CTest option (:151) and test target names are
  still pre-rebrand (ROADMAP P3 stragglers). The only other CMake files are under `tests/`.
- `build.ps1` — build driver: configure + build Win32 and/or x64, then copy artifacts to `./release`.
- `CMakePresets.json` — presets `x64` / `win32-injectee-only` mirroring the two build.ps1 passes (no copy step).
- `setup.nsi` — NSIS installer; packs `release\*.*` (:56). ⚠️ `setup.nsi:10-11` still names the pre-rebrand
  product + GUI exe, so the installer points at a binary the build no longer produces (P3 packaging item).
- `.github/workflows/build.yml` — CI: windows-2022, {Debug,Release} × {Win32,x64}; Build (:28),
  blocking `ctest` excluding e2e (:31), x64/Release e2e step with `--repeat until-pass:3` (:33-35).
- `resources/` — icon/png assets + `encapsule.rc` (GUI app icon, `CMakeLists.txt:126`).
- `docs/` — `BUILDING.md` (contributor build/debug guide) + logo and screenshot images.
- `.agents/ROADMAP.md` — roadmap + "fragile areas" notes (file:line references).
- `src/common/` — `encapsule_common`, header-only INTERFACE lib: `schema.hpp` protopuf IPC messages ·
  `utils.hpp` process/wildcard/regex matching + mapping name/token payload (:161-190) · `winraii.hpp`
  RAII handles, `virtual_memory`, `create_mapping` with explicit DACL (:143-195) · `async_io.hpp`
  length-prefixed message read/write · `queue.hpp` `blocking_queue<T>` · `minhook.hpp` CRTP MinHook
  wrapper · `version.hpp.in` → generated `version.hpp` (`:95`).
- `src/injectee/` — `encapsule-injectee.dll`, code that runs **inside the target process**:
  `injectee.cpp` (`DllMain` :88; detached client thread) · `hook.hpp` (winsock detours; includes
  `services.inc` at :272) · `services.inc` (service-name table, no guard) · `client.hpp` (IPC client,
  `injectee_config`, token hello) · `socks5.hpp` (handshake/request) · `winnet.hpp` (address helpers).
- `src/injector/` — code that runs **outside**, in the tool's own process: `injector.hpp` (mapping +
  `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`; DLL names at :190-191; token store :65-109) ·
  `server.hpp` (control server, token check :183-188) · `injector_cli.{cpp,hpp}` (argparse+spdlog) ·
  `injector_gui.{cpp,hpp}` (cycfi/elements) · `ui_elements/` (dynamic_list, text_box, tooltip widgets).
- `src/wow64/address_dumper.cpp` — Win32-only helper exe; returns the 32-bit `LoadLibraryW` address as
  its **process exit code** (`:22-26`); `#error`s if compiled as x64 (`:18-20`). Name unchanged by P3.
- `tests/` — host-side CTest suite: `schema/`, `utils/`, `winnet/`, `queue/`, `e2e/` (+ `test_support.hpp`).

Entry points (3 `main` + 1 `DllMain`): `src/injector/injector_cli.cpp:110` (`encapsule-cli`),
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
  (`:41-42`). Optional installer: `makensis /DVERSION=$(git describe --tags) setup.nsi` (see the setup.nsi caveat).
- **CMake 4.x:** every configure carries `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` (`build.ps1:26,28`, since
  d724762; also `CMakePresets.json:29`) because the FetchContent deps declare older minimums — keep it on
  any hand-rolled `cmake` configure line.
- **Version:** configure reads `git describe --tags`; on failure it warns and falls back to
  `v0.0.0-unknown` (`CMakeLists.txt:83-92`), so a tag-less clone configures fine — no workaround needed.

**Tests: host-side CTest suite; the unit tests need no injection.** On by default (`CMakeLists.txt:151-155`);
skipped under `ENCAPSULE_INJECTEE_ONLY=ON`, so the Win32 pass of an x64 run registers no tests. Run after building:

```powershell
cmake --build build/x64 --config Release -j $env:NUMBER_OF_PROCESSORS   # or: cmake --build --preset x64
ctest --test-dir build/x64 -C Release --output-on-failure -E '^e2e\.'   # CI blocking step, build.yml:31
```

- Registered tests: `common.schema`, `common.utils`, `injectee.winnet`, `common.queue` (one `add_test` per
  `tests/<mod>/CMakeLists.txt:4`; targets still carry the pre-rebrand prefix) plus `e2e.loopback_selfcheck`
  and `e2e.inject_connect` (label `e2e`, `RUN_SERIAL`, `TIMEOUT 120`). Test exes go to `build/<arch>/test_bin/`.
- `e2e.inject_connect` is a **real inject-and-connect** test (decoy process + in-process socks5 relay),
  registered only for 64-bit builds (`tests/e2e/CMakeLists.txt:60`); it is the CI e2e step's target.
- `BUILD_TESTING OFF CACHE BOOL "" FORCE` (`CMakeLists.txt:38`) silences only the *deps'* tests, not ours.

## 4. Codebase-memory index (use this for accurate tool calls)

Indexed as project **`C-dev-encapsule`** (name derived from path `C:\dev\encapsule`) — the project key is
**unchanged by the rebrand**. Root `C:/dev/encapsule`, branch `master`, mode moderate, 459 nodes / 1242
edges, packages `injector`/`common`/`injectee`/`wow64`.

⚠️ **The index predates the P3 rebrand and the P4 work — re-index before trusting it.** It has no `tests/`
tree (verified: 32 File nodes, 0 under `tests/`), and its line numbers are stale (e.g. `DllMain` moved
:48→:88, the `services.inc` include :202→:272). Its `parse_partial` ranges are therefore approximate —
`src/injectee/services.inc` (whole file), `src/injectee/hook.hpp`, `src/injector/injector.hpp`,
`build.ps1`. Use `grep`/`read` as fallback in those files.

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
  sides before changing `schema.hpp` (protopuf wire format), the mapping name/payload (`utils.hpp:161-190`)
  or the `encapsule-injectee*.dll` lookup names (`injector.hpp:190-191`).
- IPC is authenticated: the mapping carries port + 8-byte per-injection token (`utils.hpp:175-190`), the
  injectee re-presents it in every message (`client.hpp:113-121`), the server refuses mismatches
  (`server.hpp:183-188`), and the mapping gets an explicit user+SYSTEM DACL, failing closed (`winraii.hpp:143-195`).
- Two architectures in play: x64 injectee for 64-bit targets, Win32 `encapsule-injectee32.dll` +
  `wow64-address-dumper` for 32-bit targets under WoW64.

## 6. Conventions (observed in src/)

- 2-space indent, no tabs in `src/`; ~80-column clang-format style (8 lines in `injector.hpp`/`injector_gui.hpp` run to 82-109). `CMakeLists.txt`/`build.ps1` use tabs.
- Includes: `"quoted"` for same-package headers, `<angle>` for stdlib, third-party and `src/common`
  (on the include path, so `<utils.hpp>` and `"utils.hpp"` both appear).
- Header guards `ENCAPSULE_<PKG>_<NAME>` (15 headers); two `src/injector/` headers still carry the old
  guard (`injector.hpp:16`, `injector_gui.hpp:16`). No `#pragma once` anywhere.
- Every source file starts with the Apache-2.0 `// Copyright 2022 PragmaTwice` block (26/26 files);
  `ui_elements/` files additionally carry the upstream elements copyright. Attribution stays after the rebrand.
- snake_case for functions/variables and for `struct` names (`virtual_memory`, `get_port_mapping_name`);
  CRTP hook types are `hook_<winapi>`; aliases like `namespace ce = cycfi::elements`.
