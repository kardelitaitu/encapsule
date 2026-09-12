# Building from source — encapsule (contributor docs)

> Formerly `proxinject`; this tree is a fork of [PragmaTwice/proxinject](https://github.com/PragmaTwice/proxinject). Everything below uses the post-rebrand names (ROADMAP P3).

This guide is for contributors building and debugging the project from
source. For end-user installs see the [README](../README.md).

Cites into the fast-moving files (`hook.hpp`, `injectee.cpp`, `socks5.hpp`,
`server.hpp`, `injector_cli.cpp`, `injector_gui.hpp`, `udp_state.hpp`) name a
**symbol** rather than a line number, because those files move daily; every
`file:NNN` left in this guide points at a stable file.

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
3. **The client reconnects, briefly — to the same injector only.** The lost
   IPC channel is retried against the port and token it already holds, with
   bounded exponential backoff on the existing `asio::steady_timer`: 1s, 2s,
   4s, 8s, capped at 10s, for a total budget of 60s per disconnect. Every
   attempt sends a fresh `pid` hello that **re-presents the per-injection
   token** from the mapping payload, so a reconnect is authenticated exactly
   like a first session (P4 #3): a process that merely guessed the mapping
   name cannot take the channel over. That recovery only ever works while the
   injector that minted the token is still alive — see the next item.
4. **After the budget expires, nothing changes — and nothing can be
   revived.** The client stops trying but undoes nothing: the thread parks
   on an unexpiring timer so the globals the hooks read (`queue`, `config`,
   `nbio_map`) stay bound and the module stays mapped. **Reconnecting to a
   restarted injector is not possible today** — the practical recovery is to
   restart the target process and inject that. Re-injecting instead makes it
   worse: the control port is ephemeral per injector run (`auto_endpoint`,
   `src/common/async_io.hpp`), the mapping that carried port + token is a
   function-local on both sides — `injector::inject()` on the injector,
   `get_ipc_payload()` in the target — so the named section is gone once the
   first read returned, and `DllMain` never runs again for a resident module
   (a second `LoadLibraryW` is a refcount bump, so no new port or token is
   ever picked up). Meanwhile the server has dropped the token the session
   was using (`injector_server::remove` → `injector::forget_token`) while that
   second inject mints a fresh one for the same pid: the resident injectee
   keeps presenting a secret nobody holds anymore, and every hello is
   refused. Re-provisioning an already-injected process is tracked in the
   roadmap as the M1 remediation ladder — a durable mapping the client
   re-reads on each attempt is the accepted fix.

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
  DLL maps in. `DllMain` (`src/injectee/injectee.cpp`, cited by symbol)
  only initializes MinHook, installs the hooks and **detaches a worker
  thread** — the real logic (IPC client, config, logging) runs on that
  thread, so set your
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

In the target, `socks5_handshake` (`src/injectee/socks5.hpp`, cited by
symbol) offers methods `{2, 0}` when credentials are configured —
username/password first, no-auth still selectable — and `{0}` when they are not;
a server that picks method 2 gets the `{1, ULEN, user, PLEN, pass}`
subnegotiation. Any refusal
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
username/password boxes keep it out of argv. That argv window is the only
credential exposure left open: every error path encapsule itself prints is
redacted. A `-p` it cannot parse names only the authority after the last `@`,
never the userinfo, and the argument parser's `Unknown argument: <token>`
echo — thrown for anything it does not recognise — goes through
`sanitize_parse_error` (`src/injector/injector_cli.cpp`) before it reaches
stderr, so a mistyped `-palice:hunter2@1.2.3.4:1080`, a `-p=...` form or a
bare `--alice:hunter2@1.2.3.4:1080` prints `1.2.3.4:1080`; a token holding
nothing but a secret, with no authority to name, is dropped whole and leaves
only the parser's fixed prefix (measured: a bare `Unknown argument:` with
nothing after it). The net is wide as well as scrubbed: `main` catches
`const std::exception &` rather than only `std::runtime_error`, so a value the
parser cannot convert at all — `-i abc`, which argparse throws as
`std::invalid_argument`, a logic_error — is reported through the same
sanitizer and exits 1 with its fixed message plus the usage, where it used to
escape to `std::terminate` and abort the process with `0xC0000409` and an empty
stderr; a fixed-text `catch (...)` sits behind that for anything not derived
from `std::exception` at all, and it prints no value either. The practical rule
is unchanged: treat a credential typed onto the command line as visible to
whatever can read argv — but no longer as something the tool will echo back at
you.

The other detail is whitespace. Nothing unescapes or percent-decodes either
credential: `parse_proxy_url` (`src/common/utils.hpp:162-298`) treats every
character as literal, and **neither front end trims the password** — the CLI
hands the `-p` value over untrimmed and the GUI reads its password box raw,
because trimming a secret would authenticate with something nobody typed. The
asymmetry that does remain is on the *username*: the GUI trims it, the CLI
takes it literally, so ` alice` signs in from the GUI and goes on the wire as
`" alice"` from the CLI, where a server expecting `alice` refuses it. The CLI
is also stricter at the edges for the same reason — a stray space around the
host or the port is a hard parse error (exit 2), not a quiet downgrade.

### Fragile areas worth knowing when debugging

These produce the most confusing behavior inside the target process; the
full table lives in `.agents/ROADMAP.md` §2:

- **`blocking_scope` handshake — `src/injectee/hook.hpp`.** A proxied connect
  temporarily forces the socket into blocking mode (`FIONBIO = 0`) for the
  socks5 handshake, then restores the remembered mode; that state is tracked
  in `nbio_map` by the `ioctlsocket`, `WSAAsyncSelect` and `WSAEventSelect`
  hooks (sockets that never went non-blocking stay blocking). The handshake
  is bounded by a 3 s timeout (`SOCKS_HANDSHAKE_TIMEOUT_MS` in `hook.hpp`),
  applied as `SO_RCVTIMEO`/`SO_SNDTIMEO` by the `blocking_scope` constructor,
  surfacing as `WSAETIMEDOUT` — so a hung proxy fails the connect after
  ~3 s rather than hanging the victim's thread. When stepping here, check that
  the non-blocking state is restored correctly — a wrongly restored mode looks
  like an unrelated async-I/O bug in the target application.
- **Socket-type verdict — `src/injectee/hook.hpp`.** Before a routing detour
  proxifies anything it asks `socket_stream_type`, which reads
  `getsockopt(SOL_SOCKET, SO_TYPE)` and answers three ways: the provider said
  `SOCK_STREAM`, it said otherwise, or it never answered at all. A socket the
  provider rules out — `SOCK_DGRAM` above all — goes straight to the original
  connect, untouched: datagrams used to be dragged through the socks5 greeting,
  left the handshake to time out and came back `shutdown()`-ed by
  `fail_proxied_connect`, which is a bug that shipped (P7 gives UDP a relay of
  its own instead of a borrowed TCP one). An *undecided* socket — the query
  failed with `WSAENOTSOCK` on a handle another thread just closed, or
  `WSAENOPROTOOPT`/`WSAEOPNOTSUPP` behind a partially-implementing LSP,
  `WSASYSNOTREADY`/`WSANOTINITIALISED` from winsock itself — is refused the
  same way a refused proxy is when this site has a proxy configured: the
  connect reports `WSAECONNREFUSED` rather than leaking out direct, and the
  closed handle that used to answer `WSAENOTSOCK` now answers
  `WSAECONNREFUSED`. With no proxy configured there is no promise to keep, so
  the original runs. So when a target says "the proxy refused", check the
  verdict before believing the proxy: this `WSAECONNREFUSED` can mean
  encapsule could not make up its mind.
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
  (`injectee_session::process()`, `src/injector/server.hpp`). No RNG, no
  token, no injection (`src/injector/injector.hpp:114`).
- The mapping is created with an explicit user+SYSTEM DACL
  (`D:P(A;;GA;;;SY)(A;;GA;;;<current-user-SID>)`) and **fails closed**: if the
  descriptor cannot be built, the mapping is not created at all — never
  silently left world-accessible (`create_mapping`,
  `src/common/winraii.hpp:153-203`).

### Front-end click handlers: no throws, no user text

Every `on_click` handler in `src/injector/injector_gui.hpp` runs on the UI
thread, where an escaped exception is not an error message — it is the
injector process dying, and it takes the control channel of every already
encapsulated process with it. The convention is therefore that these handlers
**cannot throw**:

- `report(panel, why)` is how a handler says no: one log line, tagged with its
  panel (`[process]`, `[proxy]`), plus a repaint — and it guards its own write,
  because a throw on the way out of a `catch` ends the process just like one
  that was never caught. `guarded(action, panel, line)` is the backstop for
  what validation cannot reach (a failing allocation, asio, protopuf, a
  `std::regex` giving up), and the proxy toggle's `refuse` lambda is `report`
  plus snapping the toggle back off, which is what a rejected click looks like.
- **Refusal text is a literal at every call site; nothing typed is
  interpolated into it.** That is not tidiness — the address box takes free
  text, so echoing a paste of `user:pass@host` would park a password in a log
  that keeps every line since start-up. `parse_process_id` returning a
  `const char *` rather than a message is the same rule.
- No `std::stoul`, no `std::isdigit` on a signed char, no
  `ip::address::from_string`. Port and pid are bounded by
  `proxy_port_max_length` / `process_id_max_digits` and accumulated digit by
  digit, so port 0, a non-numeric port and an eleventh-digit pid each get one
  fixed line; addresses go through `ip::make_address(addr, ec)`, which reports
  failure instead of throwing, so a hostname is refused (nothing here resolves
  names). A bracketed IPv6 host is unbracketed first, exactly as
  `parse_proxy_url` does, so both front ends accept the same spellings.

An empty box is a refusal too: a click that used to do nothing now says so, for
the same reason — silence looks like a click that was lost.

Write new handlers this way: validate with the same rules the CLI applies to
`-p`, `report` the refusal in fixed text, and let `guarded` catch the rest.
