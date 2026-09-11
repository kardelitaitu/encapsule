# Building from source — encapsule (contributor docs)

> Rebrand note: the project is being renamed `proxinject` → `encapsule`
> (see `.agents/ROADMAP.md`, P3). Until that rebrand lands, targets, binaries
> and file names in this document still use the old `proxinject` branding.

This guide is for contributors building and debugging the project from
source. For end-user installs see the [README](../README.md).

## 1. Build prerequisites

| Requirement | Notes |
|---|---|
| Windows 10+ | Windows-only by design; `CMakeLists.txt` fails fast on non-WIN32 hosts. |
| MSVC C++20 toolset | Visual Studio 2019/2022 (Build Tools are enough) with the "Desktop development with C++" workload. MSVC is the only supported compiler; C++20 is required (`CMAKE_CXX_STANDARD 20`). |
| Windows SDK (winsock2) | Comes with the VS C++ workload. The injectee links `ws2_32`; `_WIN32_WINNT` is pinned to `0x0A00`. |
| CMake >= 3.20 | On `PATH` (`cmake_minimum_required(VERSION 3.20)`). `build.ps1` only shells out to `cmake`; the VS generator locates MSBuild for the actual compile. |
| git | Configuration runs `git describe --tags` to read the version string; when that fails (e.g. a fresh clone with **no tags**) CMake warns and falls back to `v0.0.0-unknown` (`CMakeLists.txt:82-91`), so a fresh clone configures without needing a tag. |

All third-party libraries (minhook, protopuf, argparse, spdlog, asio, the
cycfi/elements fork) are FetchContent-pinned and downloaded **at configure
time**, so the first configure needs network access. Nothing is vendored.

Note: the static CRT (`MultiThreaded` / `MultiThreadedDebug`) is deliberate —
the injectee DLL is loaded into foreign processes and must not depend on a
shared runtime. Do not switch to dynamic CRT linkage.

## 2. How to build

```powershell
./build.ps1 -mode Release -arch x64
```

Script parameters (`build.ps1`):

| Parameter | Default | Meaning |
|---|---|---|
| `-mode` | `Release` | CMake build config (`Debug`, `Release`, ...). |
| `-arch` | `x64` | `x64` or `Win32` (exact strings; anything else exits 1). |
| `-build_dir` | `build` | Where the CMake build trees are created. |
| `-release_dir` | `release` | Where the final artifacts are assembled. |
| `-skip_cmake` | off | Skip the configure step; only rebuild and copy. |

### What `-arch x64` does

1. **x64 pass** — full configure + build: the GUI (`proxinjector.exe`), the
   CLI (`proxinjector-cli.exe`) and the 64-bit `proxinjectee.dll`.
2. **Win32 pass** — a second configure with `-DPROXINJECTEE_ONLY=ON`, which
   builds *only* the 32-bit injectee, plus the Win32-only
   `wow64-address-dumper.exe` helper.
3. Both passes compile via `cmake --build <dir> --config <mode>` (MSBuild
   under the hood), and the artifacts are copied into `./release`.

`./release` then contains:

| File | Purpose |
|---|---|
| `proxinjector.exe` | GUI front end. |
| `proxinjector-cli.exe` | CLI front end. |
| `proxinjectee.dll` | 64-bit injectee, loaded into 64-bit target processes. |
| `proxinjectee32.dll` | 32-bit injectee (from the Win32 pass), for 32-bit/WoW64 targets. |
| `wow64-address-dumper.exe` | Win32 helper that reports the 32-bit `LoadLibraryW` address as its **process exit code** — the WoW64 pivot used by the 64-bit injector. |
| `resources/`, `LICENSE` | App assets and license, staged for packaging. |

`-arch Win32` runs the single Win32 pass only (all targets, 32-bit).

Optional installer (see `setup.nsi`):

```powershell
makensis /DVERSION=$(git describe --tags) setup.nsi
```

CI (`.github/workflows/build.yml`) runs the same script on `windows-2022`
with a `{Debug, Release} × {Win32, x64}` matrix.

> **CMakePresets note:** `CMakePresets.json` presets mirroring `build.ps1`
> (x64 full build + Win32 `PROXINJECTEE_ONLY=ON` pass that yields
> `proxinjectee32.dll`) are landing in parallel (ROADMAP P1). Once merged,
> `cmake --preset ...` becomes an alternative to the wrapper script;
> `build.ps1` stays the source-of-truth reference for what the presets must
> reproduce.

## 3. Debugging injected processes

`proxinjectee.dll` executes **inside the target process** and detours live
winsock APIs — a crash in injected code kills the target, so debug against
disposable processes (a small test program, a `python` REPL, ...). The
injector side (`src/injector/`) is an ordinary process and needs no special
treatment.

### Attaching a debugger to the target process

- Attach **before injecting** (Visual Studio: *Debug → Attach to Process*;
  WinDbg: `windbg -p <pid>`, or launch the target under the debugger) so you
  catch the DLL load. Once injected, `proxinjectee.dll` shows up in the
  target's module list.
- **Bitness must match**: use the x64 debugger for 64-bit targets, the x86
  debugger for WoW64 targets (those receive `proxinjectee32.dll`).
- Build `-mode Debug` for an unoptimized injectee and point the debugger's
  symbol path at the PDBs of the same build tree (`build/<arch>/<mode>/`).
- In WinDbg, `sxe ld:proxinjectee.dll` breaks the moment the injected DLL
  maps in. `DllMain` (`src/injectee/injectee.cpp`) only initializes MinHook,
  installs the hooks and **detaches a worker thread** — the real logic (IPC
  client, config, logging) runs on that thread, so set your breakpoints in
  the `src/injectee/hook.hpp` detours and `client.hpp`, not in `DllMain`.

### The connection log flag: `-l` / `--enable-log`

`proxinjector-cli -l` (and the GUI log toggle) tells the injectee to push a
`connect` message — socket handle, original destination, proxy address and
the name of the hooked API — over the IPC channel for every hooked outbound
connect; the front end prints these with timestamps. It is the fastest way
to confirm that redirection actually happened:

```powershell
# smoke test against a local socks5 server (ROADMAP §5)
./release/proxinjector-cli.exe -p 127.0.0.1:1080 -i <pid> -l
```

If a connection is *not* logged: hooks only act on AF_INET non-localhost
destinations, and only after the injectee has received its config from the
injector. `connect`, `WSAConnect`, `WSAConnectByList`, `ConnectEx` and the
async-select paths are hooked separately — the log line names which hook
fired.

### Fragile areas worth knowing when debugging

These produce the most confusing behavior inside the target process; the
full table lives in `.agents/ROADMAP.md` §2:

- **`blocking_scope` handshake — `src/injectee/hook.hpp`.** A proxied connect
  temporarily forces the socket into blocking mode (`FIONBIO = 0`) for the
  socks5 handshake, then restores the remembered mode; that state is tracked
  in `nbio_map` by the `ioctlsocket`, `WSAAsyncSelect` and `WSAEventSelect`
  hooks (sockets that never went non-blocking stay blocking). There is **no
  timeout yet** (P4): a socks5 server that never answers hangs the target's
  thread indefinitely. When stepping here, check that the non-blocking state
  is restored correctly — a wrongly restored mode looks like an unrelated
  async-I/O bug in the target application.
- **DLL self-unload — `src/injectee/injectee.cpp`.** `DllMain` spawns a
  *detached* worker thread (`do_client`) that runs the asio `io_context`;
  when the IPC client finishes, that thread calls `FreeLibrary` on the DLL
  itself. Never join it or hold references into the DLL past exit. Under a
  debugger this means breakpoints and module presence can vanish mid-session
  once the client loop exits — don't mistake the unload for a crash.
- **WoW64 exit-code pivot — `src/injector/injector.hpp`,
  `src/wow64/address_dumper.cpp`.** For 32-bit targets, the 64-bit injector
  learns the 32-bit `LoadLibraryW` address by launching
  `wow64-address-dumper.exe` and reading the address from the child's
  **process exit code**. If injection into WoW64 targets fails: confirm
  `wow64-address-dumper.exe` sits next to the injector binary, that it is
  genuinely 32-bit (it `#error`s when compiled as x64), and that its exit
  code is plausible — a failure exit code silently masquerades as a
  "function address".

Also read before changing things (ROADMAP §2): the exact detour signatures
(`src/common/minhook.hpp`; `hook_ConnectEx` bypasses the CRTP wrapper), the
surprising IPv6 byte order in `src/injectee/winnet.hpp`, and the
unauthenticated IPC mapping in `src/common/utils.hpp`.
