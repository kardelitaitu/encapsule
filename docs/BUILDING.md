# Building from source — encapsule (contributor docs)

> Formerly `proxinject`; this tree is a fork of [PragmaTwice/proxinject](https://github.com/PragmaTwice/proxinject). Everything below uses the post-rebrand names (ROADMAP P3).

This guide is for contributors building and debugging the project from
source. For end-user installs see the [README](../README.md).

## 1. Build prerequisites

| Requirement | Notes |
|---|---|
| Windows 10+ | Windows-only by design; `CMakeLists.txt` fails fast on non-WIN32 hosts. |
| MSVC C++20 toolset | Visual Studio 2019/2022 (Build Tools are enough) with the "Desktop development with C++" workload. MSVC is the only supported compiler; C++20 is required (`CMAKE_CXX_STANDARD 20`). |
| Windows SDK (winsock2) | Comes with the VS C++ workload. The injectee links `ws2_32`; `_WIN32_WINNT` is pinned to `0x0A00`. |
| CMake >= 3.20 | On `PATH` (`cmake_minimum_required(VERSION 3.20)`). `build.ps1` only shells out to `cmake`; the VS generator locates MSBuild for the actual compile. With CMake 4.x keep `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` on every configure (`build.ps1:26,28`) — the FetchContent deps still declare older minimums. |
| git | Configuration runs `git describe --tags` to read the version string; when that fails (e.g. a fresh clone with **no tags**) CMake warns and falls back to `v0.0.0-unknown` (`CMakeLists.txt:83-92`), so a fresh clone configures without needing a tag. |

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

1. **x64 pass** — full configure + build: the GUI (`encapsule.exe`), the
   CLI (`encapsule-cli.exe`) and the 64-bit `encapsule-injectee.dll`.
2. **Win32 pass** — a second configure with `-DENCAPSULE_INJECTEE_ONLY=ON`
   (`build.ps1:20,28`), which builds *only* the 32-bit injectee, plus the
   Win32-only `wow64-address-dumper.exe` helper.
3. Both passes compile via `cmake --build <dir> --config <mode>` (MSBuild
   under the hood), and the artifacts are copied into `./release`.

`./release` then contains:

| File | Purpose |
|---|---|
| `encapsule.exe` | GUI front end (target `encapsule`, declared by `include(ElementsConfigApp)`, `CMakeLists.txt:118-130`). |
| `encapsule-cli.exe` | CLI front end (target `encapsule-cli`, `CMakeLists.txt:136-139`). |
| `encapsule-injectee.dll` | 64-bit injectee (target `encapsule-injectee`, `CMakeLists.txt:105-108`), loaded into 64-bit target processes. |
| `encapsule-injectee32.dll` | 32-bit injectee — the Win32 pass's DLL renamed by `build.ps1:41`, for 32-bit/WoW64 targets. |
| `wow64-address-dumper.exe` | Win32 helper (name unchanged) that reports the 32-bit `LoadLibraryW` address as its **process exit code** — the WoW64 pivot used by the 64-bit injector. |
| `resources/`, `LICENSE` | App assets and license, staged for packaging. |

The two DLL names above are the ones the injector looks up at runtime
(`src/injector/injector.hpp:190-191`) — renaming them means changing both
sides together.

`-arch Win32` runs the single Win32 pass only (all targets, 32-bit).

`CMakePresets.json` mirrors both configure/build passes (presets `x64` and
`win32-injectee-only`), so `cmake --preset x64 && cmake --build --preset x64`
is an alternative to the wrapper script; the presets do **not** perform the
copy into `./release`, so `build.ps1` stays the reference for a full build.

Optional installer (see `setup.nsi`):

```powershell
makensis /DVERSION=$(git describe --tags) setup.nsi
```

> The old packaging straggler is gone: `setup.nsi:10-11` now define
> `NAME "encapsule"` / `APPFILE "encapsule.exe"`, i.e. exactly what `build.ps1`
> puts in `./release`, and the script installs `release\*.*` (:56) as
> `encapsuleSetup.exe` (:18).

CI (`.github/workflows/build.yml`) runs the same script on `windows-2022`
with a `{Debug, Release} × {Win32, x64}` matrix, then a blocking `ctest` step
that excludes the e2e label (`:31`) and an x64/Release-only e2e step retried
with `--repeat until-pass:3` (`:33-35`).

## 3. Injector-exit behavior

**Policy: the injectee stays resident — the injector is not the victim's
lifeline.** When `encapsule.exe` / `encapsule-cli.exe` dies, is killed,
or simply exits once its last client is gone, nothing already done to the
injected process is undone. What the victim then experiences:

1. **Hooks stay installed.** `encapsule-injectee.dll` is never unloaded on the
   mid-session IPC-loss path. The client thread used to `FreeLibrary` itself
   as soon as the IPC channel closed; that was removed (ROADMAP P4 #5),
   because any other thread of the victim can be inside a detour at that
   exact moment, and no amount of joining fixes it — the unloading thread
   cannot join the threads it is unmapping code away from.
2. **Routing is fail-closed.** The hooks keep redirecting outbound AF_INET
   connects to the **last proxy config the injector sent**, held in
   `injectee_config::pinned`, which `stop()` deliberately does not clear
   (`injectee_config::drop()` only marks the session down). If that proxy is
   gone too, connects simply fail — the honest outcome. Quietly reverting
   to a direct route is precisely the leak the tool exists to prevent.
3. **The client reconnects, briefly.** The lost IPC channel is retried with
   bounded exponential backoff on the existing `asio::steady_timer`: 1s, 2s,
   4s, 8s, capped at 10s, for a total budget of 60s per disconnect. Every
   attempt sends a fresh `pid` hello that **re-presents the per-injection
   token** from the mapping payload, so a reconnect is authenticated exactly
   like a first session (P4 #3): a process that merely guessed the mapping
   name cannot take the channel over.
4. **After the budget expires, nothing changes.** The client stops trying
   but undoes nothing — the thread parks on an unexpiring timer so the
   globals the hooks read (`queue`, `config`, `nbio_map`) stay bound and
   the module stays mapped. Restarting the injector and re-injecting the
   process gives it a new session, a new token and a new config.

Pre-session failures are unchanged and still release the DLL, because at
that point no detour is live in another thread: a missing or zero IPC port
(`get_ipc_payload()`) and a failed `hook_create_all()` both unload from a
helper thread.

## 4. Debugging injected processes

`encapsule-injectee.dll` executes **inside the target process** and detours
live winsock APIs — a crash in injected code kills the target, so debug
against disposable processes (a small test program, a `python` REPL, ...).
The injector side (`src/injector/`) is an ordinary process and needs no
special treatment.

### Attaching a debugger to the target process

- Attach **before injecting** (Visual Studio: *Debug → Attach to Process*;
  WinDbg: `windbg -p <pid>`, or launch the target under the debugger) so you
  catch the DLL load. Once injected, `encapsule-injectee.dll` shows up in the
  target's module list.
- **Bitness must match**: use the x64 debugger for 64-bit targets, the x86
  debugger for WoW64 targets (those receive `encapsule-injectee32.dll`).
- Build `-mode Debug` for an unoptimized injectee and point the debugger's
  symbol path at the PDBs of the same build tree (`build/<arch>/<mode>/`).
- In WinDbg, `sxe ld:encapsule-injectee.dll` breaks the moment the injected
  DLL maps in. `DllMain` (`src/injectee/injectee.cpp:88`) only initializes
  MinHook, installs the hooks and **detaches a worker thread** — the real
  logic (IPC client, config, logging) runs on that thread, so set your
  breakpoints in the `src/injectee/hook.hpp` detours and `client.hpp`, not in
  `DllMain`.

### The connection log flag: `-l` / `--enable-log`

`encapsule-cli -l` (and the GUI log toggle) tells the injectee to push a
`connect` message — socket handle, original destination, proxy address and
the name of the hooked API — over the IPC channel for every hooked outbound
connect; the front end prints these with timestamps. It is the fastest way
to confirm that redirection actually happened:

```powershell
# smoke test against a local socks5 server
./release/encapsule-cli.exe -p 127.0.0.1:1080 -i <pid> -l
# same, on a proxy that demands an RFC 1929 login
./release/encapsule-cli.exe -p user:pass@127.0.0.1:1080 -i <pid> -l
```

If a connection is *not* logged: hooks only act on AF_INET non-localhost
destinations, and only after the injectee has received its config from the
injector. `connect`, `WSAConnect`, `WSAConnectByList`, `ConnectEx` and the
async-select paths are hooked separately — the log line names which hook
fired.

### socks5 authentication (RFC 1929)

Both front ends take an optional proxy login: the CLI inside `-p`
(`[user[:pass]@]host:port`, e.g. `user:pass@127.0.0.1:1080`), the GUI as
separate username/password boxes. `parse_proxy_url` (`src/common/utils.hpp`)
— shared and pure — splits the userinfo at the LAST `@` and the password at
the FIRST `:` after it, so a password containing `@` or `:` needs no
escaping; an IPv6 host must arrive bracketed (`[2001:db8::1]:1080`). The pair
then rides to the injectee as `InjectorConfig` fields 4/5
(`src/common/schema.hpp:90-94`): optional and separate, and an unset field
adds no bytes, which is what keeps a credential-free config byte-identical
to the pre-P5 wire.

In the target, `socks5_handshake` (`src/injectee/socks5.hpp:268-324`) offers
methods `{2, 0}` when credentials are configured — username/password first,
no-auth still selectable — and `{0}` when they are not; a server that picks
method 2 gets the `{1, ULEN, user, PLEN, pass}` subnegotiation. Any refusal
(the usual `{1, 0xFF}`, a short read, an unexpected version) fails the
handshake and `fail_proxied_connect` in `src/injectee/hook.hpp` surfaces it
as `WSAECONNREFUSED`: never a silent retry without authentication, never a
direct leak. And nothing stores or echoes a secret — the CLI logs the user
name plus the password *length* once at start-up
(`src/injector/injector_cli.cpp`), connection reports carry no credential
field (`src/common/schema.hpp:58-67`), and the GUI keeps credentials in memory
only (they are visible on screen: elements has no masked password box, see
`src/injector/injector_gui.hpp`).

Two front-end details are worth knowing before you rely on any of the above.
The CLI takes the endpoint as an argument, so the whole
`[user[:pass]@]host:port` string — password included — sits in the process
command line, where any same-user process and any process-audit provider
(Sysmon EID 1 logs it verbatim) can read it; the GUI's separate
username/password boxes keep it out of argv. Nothing else about the CLI is
loose, though: a rejected `-p` names only the authority after the last `@`,
never the userinfo, so the error path cannot echo the secret either.

The other detail is whitespace. Nothing unescapes or percent-decodes the
password: `parse_proxy_url` (`src/common/utils.hpp:162-298`) treats every
character as literal, and the CLI hands it the `-p` value UNTRIMMED on purpose
— trimming there would authenticate with a different secret than the one that
was typed, so a stray space around the host or the port is a hard parse error
instead of a quiet downgrade. The GUI is not symmetric yet: it trims every box
it reads — host, username and password alike — so a password with meaningful
leading or trailing whitespace can only be entered from the CLI.

### Fragile areas worth knowing when debugging

These produce the most confusing behavior inside the target process; the
full table lives in `.agents/ROADMAP.md` §2:

- **`blocking_scope` handshake — `src/injectee/hook.hpp`.** A proxied connect
  temporarily forces the socket into blocking mode (`FIONBIO = 0`) for the
  socks5 handshake, then restores the remembered mode; that state is tracked
  in `nbio_map` by the `ioctlsocket`, `WSAAsyncSelect` and `WSAEventSelect`
  hooks (sockets that never went non-blocking stay blocking). The handshake
  is bounded by a 3 s timeout (`SOCKS_HANDSHAKE_TIMEOUT_MS`, `hook.hpp:66`),
  applied as `SO_RCVTIMEO`/`SO_SNDTIMEO` in `blocking_scope` (`hook.hpp:111-121`)
  and surfacing as `WSAETIMEDOUT` — so a hung proxy fails the connect after
  ~3 s rather than hanging the victim's thread. When stepping here, check that
  the non-blocking state is restored correctly — a wrongly restored mode looks
  like an unrelated async-I/O bug in the target application.
- **Injector exit — `src/injectee/injectee.cpp`, `client.hpp`.** `DllMain`
  spawns a *detached* worker thread (`do_client`) that runs the asio
  `io_context`. It no longer calls `FreeLibrary` on the DLL when the IPC
  channel closes: the injector dying must not unmap code that other threads
  of the victim may be executing inside a detour. The module therefore stays
  mapped for the lifetime of the process — see §3 for the whole policy, and
  stop expecting the unload that used to make breakpoints and module
  presence vanish mid-session.
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
surprising IPv6 byte order in `src/injectee/winnet.hpp`, and the IPC mapping
contract below.

### The IPC mapping: name, payload and DACL

- The mapping name is `ENCAPSULE_PORT_IPC_<pid>` (`src/common/utils.hpp:300-304`).
  Both sides must agree on it — renaming it is a two-sided change.
- The payload is not just the port: `port_mapping_payload` carries the control
  port plus an 8-byte per-injection random token (`src/common/utils.hpp:306-329`,
  built by `get_port_mapping_payload`, :334-351), and the injectee re-presents
  that token in every message it sends (`src/injectee/client.hpp:113-123`). The
  control server refuses any session whose token does not match
  (`src/injector/server.hpp:217-229`). No RNG, no token, no injection
  (`src/injector/injector.hpp:114`).
- The mapping is created with an explicit user+SYSTEM DACL
  (`D:P(A;;GA;;;SY)(A;;GA;;;<current-user-SID>)`) and **fails closed**: if the
  descriptor cannot be built, the mapping is not created at all — never
  silently left world-accessible (`create_mapping`, `src/common/winraii.hpp:150-200`).
