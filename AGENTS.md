# AGENTS.md — proxinject

Facts here were read from the cited sources (`master@f2d3027`). Re-verify after refactors.

## 1. Project overview

proxinject is a **Windows-only socks5 proxy injection tool**: it injects `proxinjectee.dll`
into a running process, redirects that process's outbound TCP connections through a
user-supplied socks5 server, and reports connections back to a GUI or CLI front end.
Toolchain: MSVC + Windows SDK (winsock2), C++20, CMake >= 3.20, driven by `build.ps1`.
Third-party deps are FetchContent-pinned and downloaded at configure time — nothing is vendored.

## 2. Repository layout

- `CMakeLists.txt` — the **only** CMake file (no per-directory CMakeLists); all targets live here.
- `build.ps1` — build driver: configure + build Win32 and/or x64, then copy artifacts to `./release`.
- `setup.nsi` — NSIS installer script; packs `release\*.*` (setup.nsi:56) into `proxinjectSetup.exe`.
- `CMakeSettings.json` — Visual Studio IDE configs (Ninja, x64/x86); **not** used by build.ps1.
- `.github/workflows/build.yml` — CI: windows-2022, matrix {Debug,Release} x {Win32,x64}, runs build.ps1 (:28).
- `resources/` — icon/png assets + `proxinject.rc` (GUI app icon, CMakeLists.txt:111).
- `docs/` — logo and screenshot images only; no prose documentation.
- `.agents/ROADMAP.md` — roadmap + "fragile areas" notes (file:line references).
- `src/common/` — `proxinject_common`, an INTERFACE header-only lib (CMakeLists.txt:94-96):
  `schema.hpp` protopuf IPC messages · `utils.hpp` process/wildcard/regex matching + IPC mapping name
  (:156) · `winraii.hpp` RAII handles / `virtual_memory` / `mapped_buffer` · `async_io.hpp` asio
  length-prefixed message read/write · `queue.hpp` `blocking_queue<T>` · `minhook.hpp` CRTP MinHook
  wrapper · `version.hpp.in` → generated `version.hpp` (CMakeLists.txt:92).
- `src/injectee/` — `proxinjectee.dll`, code that runs **inside the target process**:
  `injectee.cpp` (`DllMain` :48, spawns client thread, self-`FreeLibrary`) · `hook.hpp` (winsock
  detours; includes `services.inc` at :202) · `services.inc` (service-name table, no guard) ·
  `client.hpp` (IPC client + `injectee_config`) · `socks5.hpp` (handshake/request) · `winnet.hpp`
  (WinSock2 address helpers).
- `src/injector/` — code that runs **outside**, in the tool's own process:
  `injector.hpp` (mapping + `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`) ·
  `server.hpp` (control TCP server, `injectee_session`) · `injector_cli.{cpp,hpp}` (argparse+spdlog) ·
  `injector_gui.{cpp,hpp}` (cycfi/elements) · `ui_elements/` (custom widgets: dynamic_list, text_box, tooltip).
- `src/wow64/address_dumper.cpp` — Win32-only helper exe; returns the 32-bit `LoadLibraryW`
  address as its **process exit code** (`:22-26`). Guarded by `#error` if compiled as x64 (`:18-20`).

Entry points (3 `main` + 1 `DllMain`): `src/injector/injector_cli.cpp:110` (`proxinjector-cli`),
`src/injector/injector_gui.cpp:41` (`proxinjector`), `src/wow64/address_dumper.cpp:22`
(`wow64-address-dumper`), and `src/injectee/injectee.cpp:48` `DllMain` (`proxinjectee`).

## 3. Build & verify

```powershell
./build.ps1 -mode Release -arch x64     # the documented build command (README, build.yml:28)
```

Params (`build.ps1:1-7`): `-build_dir` (default `build`), `-release_dir` (`release`), `-mode`
(`Release`), `-arch` (`x64`), `-skip_cmake` switch. Verified semantics:

- `-arch` accepts **exactly** `Win32` or `x64`; anything else exits 1 (`build.ps1:13-16`). `x86`/`amd64` are invalid.
- `-arch x64` runs **two** passes: full x64 configure (`:26`) plus a Win32 configure with
  `-DPROXINJECTEE_ONLY=ON` (`:20,28`) so only the 32-bit DLL is built there.
- `-arch Win32` runs the single Win32 pass with all targets.
- Compile step: `cmake --build <dir> --config $mode -j $env:NUMBER_OF_PROCESSORS` (`:32,34`).
- Artifacts land in `./release` (`:36-38`): `proxinjector.exe`, `proxinjector-cli.exe`,
  `proxinjectee.dll`; an x64 run also copies `proxinjectee32.dll` + `wow64-address-dumper.exe` (`:41-42`).
- Optional installer: `makensis /DVERSION=$(git describe --tags) setup.nsi` → `proxinjectSetup.exe`.

**Configure gotcha (verified):** configuration runs `git describe --tags` and emits
`FATAL_ERROR` when it fails (`CMakeLists.txt:82-89`). This clone has **no tags**
(`git tag -l` is empty), so a fresh build fails there until you create one, e.g. `git tag v0.0.0`.

**Tests: there is no automated test suite — verify via a successful build.** No `add_test()` /
`enable_testing()` exists in any CMakeLists, and a `**/*test*` glob matches no file.
(`set(BUILD_TESTS OFF ...)` at `CMakeLists.txt:37` only silences protopuf's own tests.) CI
(`build.yml`) likewise only builds and packages.

## 4. Codebase-memory index (use this for accurate tool calls)

Indexed as project **`C-dev-encapsule`** (name derived from path `C:\dev\encapsule`), root
`C:/dev/encapsule`, branch `master`, mode moderate, **459 nodes / 1242 edges** (verified via
`list_projects` / `index_status`). Packages: `injector` (127 nodes), `common` (69),
`injectee` (53), `wow64` (1). Measured boundaries (calls): injector→common 38, injectee→common 18,
injector→injectee 10, injectee→injector 3.

Caveat — 4 files are `parse_partial` (indexed, but constructs in these ranges MAY be missing;
use `grep`/`read` as fallback there):
- `src/injectee/services.inc` lines 1-292 (whole file)
- `src/injectee/hook.hpp` lines 87, 201-203, 238, 321
- `src/injector/injector.hpp` line 78
- `build.ps1` lines 9-10, 26, 28, 32, 34, 36-38, 41-42

Re-index after structural changes: `mcp cbm index_repository(repo_path="C:\dev\encapsule", mode="moderate")`.
Prefer `search_graph` / `trace_path` / `get_code_snippet` over bulk reading; `detect_changes({})` for blast radius.

## 5. Environment notes

- Windows host, PowerShell for the build wrapper; needs MSVC + Windows SDK discoverable by CMake
  (`build.ps1` shells out to `cmake` only; the VS generator locates MSBuild). `cmake` must be on PATH.
- C++20 (`CMAKE_CXX_STANDARD 20`, CMakeLists.txt:26), static CRT
  `MultiThreaded$<CONFIG:Debug>:Debug` (`:28`), `_WIN32_WINNT=0x0A00` + `UNICODE` (`:80,96`).
- **Injected vs. injector code:** everything in `src/injectee/` executes inside a *foreign* process
  (hooks live winsock APIs; a crash kills the target; `DllMain` must not block; the DLL unloads itself).
  `src/injector/` executes in the tool's own process. `src/common/` is compiled into both — check
  both sides before changing `schema.hpp` (protopuf wire format) or the mapping name at `utils.hpp:156`.
- Two architectures are in play: x64 injectee for 64-bit targets, Win32 `proxinjectee32.dll` +
  `wow64-address-dumper` for 32-bit targets under WoW64.

## 6. Conventions (observed in src/)

- 2-space indent, no tabs in `src/`; 80-column limit (max line width across all 26 files is exactly 80);
  clang-format-style wrapping. `CMakeLists.txt` / `build.ps1` use tabs.
- Includes: `"quoted"` for same-package headers, `<angle>` for stdlib, third-party and `src/common`
  (which is on the include path, so `<utils.hpp>` and `"utils.hpp"` both appear).
- Header guards `#ifndef PROXINJECT_<PKG>_<NAME>` (17 headers); no `#pragma once` anywhere.
- Every source file starts with the Apache-2.0 `// Copyright 2022 PragmaTwice` block (26/26 files).
- snake_case for functions/variables and for `struct` names (`virtual_memory`, `hook_ioctlsocket`,
  `get_port_mapping_name`); CRTP hook types are `hook_<winapi>`; aliases like `namespace ce = cycfi::elements`.
