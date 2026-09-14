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
      SPLIT by risk dossier (bc8f57cb, offline tag sets from build/x64/_deps/*/.git/packed-refs,
      so 'newest' = current-as-of-last-configure, not live):
      (a) spdlog 1.10.0 -> 1.17.0 — SAFE-ISH, CLI-only (2 includes + 10 calls), but the real
          content is bundled fmt 8.1.1 -> 12.1.0 (fmt 9/10/11/12 breaking changes under our
          {} format strings). Gate: full unit ctest + read injector_cli's output by eye.
      (b) argparse 2.9 -> 3.2 — CLI-only, +1103/-167 in one header. MEASURED: the literal our
          redaction depends on, '"Unknown argument: " + current_argument', is UNCHANGED at
          v3.2:2451/2455; v3 ADDS an 'Invalid argument <x>' form we do not yet scrub, and NO
          TEST asserts CLI error text at all -> pin the redactor FIRST (see (f)), then bump.
      (c) asio 1.22.2 -> cap at 1.30.0/1.36.0, NEVER >= 1.38.0: at 1.38 the headers moved from
          asio/include/... to include/asio/... and our layout is HARDCODED IN 9 PLACES
          (CMakeLists.txt:70,108,130,139 + tests/{schema,queue,socks5,e2e,winnet}/CMakeLists.txt),
          including ELEMENTS_ASIO_INCLUDE_DIR — i.e. asio and elements are coupled through the
          same copy, so the two bumps cannot be evaluated independently. queue.hpp is NOT on a
          private surface: it names only documented experimental channel members (ctor with
          (executor,max), async_send/async_receive, cancel, close); the one API delta we could
          feel is get_executor() returning const-ref since 1.24/1.3x. Oracle already exists:
          ctest -R '^common\.queue$' (7 scenarios incl. the pushed==delivered+dropped+queued
          identity). Prereq refactor: hoist one asio_INCLUDE_DIR variable over those 9 sites.
      (d) minhook 49d03ad (v1.3.3+22) -> v1.3.4 — the pin-to-tag delta touches ONLY thread
          freeze hardening (SuspendThread != 0xFFFFFFFF, unsuspendable -> never resumed,
          Mitigates #132); the Create/Remove/EnableState machine our REVERSE-ORDER UNROLL
          depends on is textually unchanged, and that is load-bearing because every remove()
          runs on a created-but-never-enabled hook. To origin/master instead = hde32/hde64 +
          trampoline rewrites (+257/+341) = instruction relocation on LIVE winsock prologues,
          which only the e2e legs can catch and they crash the VICTIM, not the test. Tag only.
      (e) protopuf v2.2.1 -> v3.1.0 — DELIBERATELY DEFERRED, do not do it in this chore: v2.2.1
          is the last release before the major that crosses the FROZEN P5 WIRE CONTRACT
          (fields 4/5, credential-free config byte-identical to pre-P5) and common.schema is the
          ONLY guard; silent encode drift compiles green on both sides and misbehaves in the
          victim. Zero product benefit.
      (f) elements 8e4dfff — NOTHING TO BUMP TO: our pin IS PragmaTwice/elements origin/master
          tip (0 ahead/0 behind; develop is 25 behind), the string-view-lite copy lives in the
          NESTED lib/infra submodule @f3e33fe -> external/string-view-lite v1.4.0, there is no
          PATCH_COMMAND anywhere in our build, so a bump cannot move it. Making this real means
          re-forking onto cycfi/elements or carrying a patch.
      CORRECTION TO OUR OWN DOCS (measured this session, MSVC 14.44.35207, exact vcxproj flags):
      cl /Zs passes for injector_gui.cpp + all three ui_elements/*.cpp + elements' own
      lib/host/windows/*.cpp, and a real 'cl /c /std:c++20 /MT /O2 injector_gui.cpp' -> exit 0
      (20 warnings), with /showIncludes PROOFING nonstd/string_view.hpp:117-122 is in the graph.
      So the documented 'string_view.hpp(120): C2143/C2447 is the only compile error in the
      project' DOES NOT REPRODUCE — the true GUI gap is that elements.lib has never been built
      or LINKED here (0 .obj in encapsule.dir/Release, 0 .lib in _deps/elements-build), which
      points at the fork's in-tree prebuilt /MT externals (cairo/fontconfig/freetype/pixman/
      expat/png16) and RuntimeLibrary ABI agreement, not at a parse error. Decisive probe:
      build --target encapsule ONCE in the isolated worktree and read whether the first failure
      is a parse error (dep) or LNK1104/LNK2038 (ABI). AGENTS.md §3's claim to be updated once
      that probe lands.
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
      for 60s against the port it already knows, fail-closed routing via pinned
      config, docs §3; kill-probe: routing 3ms post-kill, retry hello at 1.006s.)
      ⚠ SCOPE CORRECTED by races review 4c67ea5c + design dossier: the probe evidenced
      RETRY and RESIDENCY only — re-registration was never proven and cannot work today
      (token forgotten on every session loss + ephemeral control port + one-shot
      mapping), so a transient reset OR an injector restart leaves a resident victim
      unmanageable. Remediation ladder M1-a..f accepted (A now: stop forgetting;
      C-lite: durable mapping re-read per attempt = the real fix; B rejected —
      re-inject cannot re-enter DllMain). BUILDING.md's re-inject promise fixed too.
      M1-a LANDED (54cdae4/fccdc60, pushed): session_end {lost, retired} with NO default arg,
      kept_bootstraps LRU cap 4096 as a leaf lock; pinned by 9e180e2 (tests/server, mutation-
      proven both ways). M1-b LANDED (57a748f, pushed): mapping held per-pid + publish/load
      split. M1-d LANDED (c46bbe1 + f34f7ee + 4a9587e + b6855c6, all pushed): both front
      ends now say 'already encapsulated' vs 'injected', the GUI names its three refusals
      ('the server is not listening yet' / 'that process is already in the list' / 'the capsule
      did not attach'), and 38 lines of duplicated IsWow64Process+module-walk were DELETED from
      injector_gui.hpp once server.inject returned the verdict. CLI has no refusal text yet. STILL OPEN: M1-c (client re-read of the mapping
      per attempt) and the adopt-vs-already-resident channel — a RESIDENT capsule has no way to
      receive a new port+token, because the server only pushes InjectorConfig down an
      already-authenticated socket; -i on a resident pid still publishes a token nobody reads.
      🐛 FIXED BY THE WAY (f34f7ee, BEHAVIOR CHANGE OWNED): injector_server::inject()'s
      'not started' guard was DEAD CODE — 'port_ == -1' on a std::uint16_t compares 65535 to
      -1, so an un-started server fell through into a real injector::inject() carrying port
      65535 in the mapping payload: a capsule wired to a control port that does not exist.
      Latent for both front ends in the common case, but the GUI sets the port on the detached
      do_server thread while the app thread answers clicks, so the FIRST CLICK after startup
      could win that race. Now a named no_port = 0xffff sentinel makes the case real and
      fail-closed. LESSON FOR THE ROADMAP'S FRAGILE-AREAS LIST: never compare a uint16_t port
      against -1; and port_ is still a plain uint16_t written from the io thread and read from
      the front-end thread (documented race, narrower now).
      ⚠ MEASURED (fd745e7, disabled probe e2e.inject_exec): a brand-new '-e' child's FIRST
      connect goes DIRECT ~0.4s before its config lands (relay 1 CONNECT vs sink 1 direct
      accept at 617ms; attempt #1 RST by the witness, attempt #2 round-trips once hooked).
      Harness caveat found on the way: the in-repo relay CANNOT see a direct connect (it
      drops a non-SOCKS greeting unrecorded) and TEST-NET-3 dials black-hole, and loopback
      is exempt by policy, so a leak-proof needs a NON-LOOPBACK witness sink and
      'ordering + hard zero' assertions (never 'count >= N'). A-chain (CREATE_SUSPENDED +
      resume on verified hello + bounded pre-config park) is now evidence-backed, not
      cosmetic; it waits on M1-a/M1-d freeing server.hpp + injector.hpp.
      ✅ M5 CONSUMER LANDED (7ae8623b @ d966b93): the injectee's report queue is now bounded
      at 1024 — NOT the 4096 this roadmap asked for, and the lane was right to override: a
      push() posts one token per item and the asio channel buffers only 'max' (1024), so a
      larger bound re-creates the stranded-async_send half of what M5 closes. Cap is defined
      FROM kReportQueueTokens so both knobs move together.
      ⚠ OPEN (needs a 4-file chain, filed not started): drops() has NO consumer — a user
      cannot see that reports were dropped. Surface needs client.hpp (read at report time)
      -> server.hpp -> a schema.hpp report field -> GUI/CLI log; schema is the frozen P5
      contract, so this is an additive-field decision, not a quick edit.
- [x] Audit partial injection failure: mapping cleanup and no half-initialized hooks
      left in the target process. (256e27d fail-safe mapping + verified load result;
      41369fd reverse-order hook unroll + DllMain never live half-initialized + WSA refcount guard.)
      ✅ C2 RESOLVED (R2 @ 7593252, manager-verified e2e 3/3): the port-0 path no longer
      FreeLibrary's a live hook set and polls the bootstrap mapping ~4.75s, so a late-published
      mapping attaches 109ms later where it previously NEVER attached (ipc_conns=0 forever).
      Corrected intel: the reviewer's 'AV on the next winsock call' did NOT reproduce —
      DLL_PROCESS_DETACH restores the stubs first; the defect was SILENT PERMANENT capsule loss,
      not a crash.
      ✅ C4 RESOLVED (49069da2 @ 12e46f1, pushed, isolated double-run evidence): the three
      scope-bound globals publish via std::atomic_ref (release in ctor, release-nullptr in
      dtor) and are read through ONE acquire load_scope(); 13 loads + 3 deleted guards = 15
      sites, grep-verified clean by the race review. Measured on MSVC x64 /O2 without TSan:
      PRE 1094 'test said non-null, use found null' events in 3s -> POST 0 by construction.
      Honest limits (review 10df26db): the release/acquire half is STRUCTURAL, not measured —
      x86-TSO lowers both to plain mov, so 'saw-unpublished-object=0' was the only possible
      result; and lifetime of the POINTED-TO objects is NOT bought by acquire at all, it is
      guaranteed 100% by residency (the null-before-free order only narrows a window that
      cannot currently open).
      ⚠ C4 REVIEW BLOCKER (fix in flight, same lane): do_client had no try/catch, so an
      asio ctor/run exception unwinds the three guards and FREES qu/cfg/sock_map while the
      detours stay enabled and victim threads keep calling connect — the AV-in-the-victim
      window reached by unwinding. Fix = non-unwinding body falling into the existing park
      loop + a compile-time static_assert on atomic_ref alignment (MSVC's own check is
      _STL_ASSERT, Debug-only; Release degrades to _Analysis_assume_) + a real test pin.
      STILL OPEN: ~nbio_mutex (hook.hpp static) runs its dtor at DLL_PROCESS_DETACH while a
      thread may sit in nbio_store — that half is C3's detach policy, untouched.

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
- [x] E2E: verify against a socks5 server that requires authentication.
      (ea12f75 + 91d4d2c; e2e.inject_auth green: accepted login reaches CONNECT,
      refused login leaves 0 CONNECTs / 0 echoes / nonzero exit. The earlier red was
      the test's own 18s decoy deadline expiring inside the ~21.3s pre-injection
      connect — NO config-apply defect, nothing leaked direct. Retracts the false
      'fail-open' annotation of dfc82f4.)

### P6 — Feature: DNS resolution hooking
- [x] Decide the strategy: fake-IP domain mapping vs. pass-through resolution with
      remote resolve at the proxy (`ATYP=3` domain requests already exist in
      `socks5_request`). (794a9069 dossier, accepted: HYBRID — hand the app a fake IP
      from 198.51.100.0/24 (TEST-NET-2, v6 as ::ffff:<fake>) so no DNS query leaves the
      capsule, then reverse-map fake->name at the connect sites so the WIRE keeps
      ATYP=3 remote-resolve; no-TTL LRU + quarantine ring because a reused fake IP
      misrouting live traffic is the worst failure; never fake NetBIOS/.local/.arpa/
      _msdcs/WPAD; the startup window resolves via the original rather than black-holing;
      CORRECTED PREMISE (dossier fd728755, accepted): DO NOT substitute the ADDRINFO
      chain and DO NOT hook freeaddrinfo. Rewrite the REAL chain in place — overwrite only
      the 4 address octets of ai_addr (AF_INET, or AF_INET6 as ::ffff:<fake>), guarded by
      ai_addrlen >= sizeof(sockaddr_in), port untouched — so the block, ai_canonname, every
      pointer and the free all stay the VICTIM's: no allocator, no side table, no magic
      header, no ABA on a recycled pointer, and it cannot corrupt a victim's memory. The old
      'static CRT therefore must hook freeaddrinfo' reasoning was doubly wrong: getaddrinfo/
      freeaddrinfo are ws2_32 EXPORTS, not CRT, and the hook is only needed by substitution.
      Consequence accepted: multi-family chains, per-entry canonname and v6-native names are
      NOT faked (fall back to the real answer — the cheap direction).
      Nameless-fake policy: in-range + table MISS => refuse via fail_proxied_connect when a
      proxy is set, original call when not (same shape as the `unknown` verdict branch, and
      strictly AFTER the stream-classification gate so it can never bypass it). Never a quiet
      direct route: a direct path to a fake is a documented-range blackhole AND a doctrine
      violation, and the refusal is free because that connect fails either way.
      Pin only inside the detour frame (getaddrinfo has no SOCKET arg, so a resolve-time pin
      can never be balanced -> leaks a pin per name). Do-not-fake gates before touching the
      chain: no_fake_name (+AD suffix, cached via one GetComputerNameExW under the table
      lock, because no_fake_name(name,"") is the PERMISSIVE overload), literal node,
      AI_NUMERICHOST|AI_PASSIVE|AI_CANONNAME|AI_ALL|AI_PROXY, ai_socktype not STREAM/0,
      AF_INET6 without AI_V4MAPPED, no route.proxy, alloc() -> nullopt.
      Table owner: function-static fake_ip_table + mutex behind ONE inline getter (no fourth
      scope-bound global, no load_scope window, residency by construction). Gap found and
      being fixed (0bc96339): 'excluded' was ctor-only while the proxy literal is runtime —
      198.51.100.7 as the user's proxy would be handed back as a fake => invisible proxy loop.
      V6 TRAP RULE: the fake path may only ever produce a DOMAIN IpAddr, never a v6 one —
      to_ip_addr stores v6_addr REVERSED while to_asio/socks5_build_request_from_ip_addr read
      wire order (pinned at tests/winnet). Do not let P6 depend on P4-1 fixing that.
      REPORTING: no schema change (confirmed) — syscall is free text rendered verbatim by both
      front ends, so syscall="connect+fake" costs nothing, while a real field would break
      tests/schema's InjecteeConnect::size==4 credential-safety pin for information already on
      the wire; report the RECOVERED NAME in addr.domain, not the fake.
      SLICES (S1 sockaddr->octets normalizer + tri-state verdict, new fake_map.hpp +
      tests/fake_map, NO hook.hpp edit | S2 single owner/exclusion | S3 reverse-map at the 3
      sockaddr sites (connect/WSAConnect, ByList, ConnectEx — ByName/ByNameW already carry a
      DOMAIN IpAddr and need nothing) | S4 getaddrinfo/GetAddrInfoW emission | S5 syscall
      "+fake" | S6 e2e decoy proving the relay saw ATYP DOMAINNAME + a 300-name churn count)
      KILL LIST #1 ANSWERED (9b49f964, static PE import parse; own parser - no dumpbin on this
      host; limits: GetProcAddress-resolved names invisible, nss3.dll imports WSA* BY ORDINAL,
      SysWOW64 twins NOT checked (we inject 32-bit targets), no delay-load):
        SEES ws2 getaddrinfo/GetAddrInfoW: curl.exe; git libcurl-4.dll + git.exe (also
        gethostbyname); CPython _socket.pyd (python3xx.dll itself has NO addrinfo import ->
        delegates); Code.exe/Electron; wezterm (Rust, +WINHTTP); winhttp.dll/wininet.dll
        reference WS2_32 and NOT DNSAPI, so WinHTTP apps stay on the hookable path.
        BYPASSES: chrome.dll 153 imports GetAddrInfoExW/GetAddrInfoExCancel + carries
        DnsClient/dns_over_https (its async/DoH resolver owns the answer); Firefox
        xul.dll+nss3.dll via PR_GetAddrInfoByName/PR_EnumerateAddrInfo (WSOCK32 by ordinal);
        node v22 is SPLIT (GetAddrInfoW for dns.lookup AND ares_/cares strings for
        dns.resolve*); System.Net.NameResolution.dll PREFERS GetAddrInfoExW (pwsh/dotnet
        apphosts show zero net imports, delegating to hostpolicy).
        DISQUALIFYING CASE: cloudflared (Go) imports NO ws2_32 and NO dnsapi at all (9
        api-ms-crt imports) + go:buildid/runtime.goexit + LoadLibrary-style strings ->
        pure-Go UDP resolver. Nothing in a winsock/ws2 detour set can see it.
      CONSEQUENCES ADOPTED: (i) HOOK THE FAMILY BY EXPORT ADDRESS, not 'getaddrinfo' —
      getaddrinfo, GetAddrInfoW, GetAddrInfoExW (+ ExCancel/FreeAddrInfoExW),
      gethostbyname/gethostbyaddr; export-address detouring is what covers ordinal imports
      (nss3), and a getaddrinfo-only hook silently misses .NET/PowerShell and part of Chrome.
      (ii) CLAIMS SHRINK to: covers CRT/WS2 users (curl, libcurl/git, CPython, Electron, WinHTTP
      apps, wezterm); Chromium's network service, Firefox/NSPR+DoH, c-ares and Go resolve for
      themselves and need separate study — still the majority of realistic targets, so S4 is
      worth building. (iii) FRAMING, the part that matters most: a private resolver gets a REAL
      ip and connects to it, and ONLY the existing connect() hook captures that, so fake-IP is
      ADDITIVE (it survives name caching and apps that refuse literal-IP proxies) and is NEVER
      the coverage mechanism. Do not let README/ROADMAP imply otherwise. (iv) BEFORE S4 ships,
      spend the ~0.5-day DYNAMIC probe: a log-only scratch injectee detouring those exports,
      recording name + entry point + caller module!RVA (RtlCaptureStackBackTrace), injected
      into chrome/firefox/Code/python/curl/git push. It answers what static analysis cannot:
      which entry point is hit in practice, whether resolution happens in a SEPARATE PROCESS
      (Chromium network service vs browser — a hook in the wrong process fakes nothing), and
      the per-victim hit rate to rank remaining work.
      #2 is capacity: half the /24 is quarantined by default so steady state is
      ~127 names and a connect-time refusal is a HARD user-visible failure, so S6 must count
      them; #4 hook.hpp contention — S3/S4/S5 all rewrite the same five hunks, rebase each on
      the landed tree, never hand-merge route/creds/q lines.)
- [ ] Hook the RESOLVER FAMILY by export address — `getaddrinfo`, `GetAddrInfoW`,
      `GetAddrInfoExW` (+ `GetAddrInfoExCancel`/`FreeAddrInfoExW`), `gethostbyname`/
      `gethostbyaddr` — via the CRTP MinHook wrapper. Export-address detouring is required
      because some victims import these APIs BY ORDINAL (nss3.dll), and a getaddrinfo-only
      hook silently misses .NET/PowerShell and part of Chromium (kill list #1, above).
      Currently absent (grep-verified), so DNS leaks outside the tunnel.
- [ ] Preserve async semantics for overlapped resolution paths (interplay with the
      existing `WSAAsyncSelect`/`WSAEventSelect` hooks).
- [ ] Emit DNS events into the existing connection-log pipeline.
- [ ] Tests: mapping-table unit tests; E2E check that no DNS query leaves the tunnel.

### P7 — Feature: UDP support (owner-approved)
- [x] Survey the datagram API surface to hook: `sendto`, `WSASendTo`, `recvfrom`,
      `WSARecvFrom`, plus connected-UDP `send`/`recv` on `SOCK_DGRAM` sockets. (794a9069
      dossier: P7a = the four To-variants ONLY, served from our own queues; connected-UDP
      `send`/`recv` + event/IOCP/`select`-driven delivery = P7b because every app shape we
      do not intercept is a HANG not a leak — so a socket is taken over only on its first
      `sendto` and is marked permanently unmanaged (reported as `syscall="udp-direct"`)
      the moment `WSAAsyncSelect`/`WSAEventSelect`/overlapped reads appear on it. Survey
      also found the shipped C0 bug: no SO_TYPE gate meant DGRAM `connect()` was
      TCP-proxified and destroyed — fixed independently at 17c3627.)
- [x] Implement the SOCKS5 UDP ASSOCIATE client (RFC 1928 §7): TCP control request,
      relay endpoint reply, datagram header (FRAG/ATYP/addr/port). (5c9fd91:
      `socks5_associate` + `socks5_relay_endpoint` (v4/v6 ready `sockaddr`, name kept raw and
      REFUSED via the 5th verdict `bnd_is_a_name` — resolving it would be an unproxied
      synchronous lookup inside the victim) + `socks5_read_reply`, with today's
      `socks5_request`/`_send` kept as one-line delegates so hook.hpp's 4 sites are untouched.
      Built on 7da5e32 (byte-pinned builders) + 8053eae (pure state). ANY verdict but `ok`
      kills the control socket (refuse + one report per peer; never silent direct).
      Bonus defect closed here: the old reader had no MSG_WAITALL and then judged
      buf[1]/buf[3] — octets of ITS OWN request buffer (`05 00 00 01` for 0.0.0.0:0), so a
      2-byte reply read back as "success, IPv4 BND" and the next recv returning 0 completed a
      PHANTOM TUNNEL. Pinned + manager-gated 7/7 at 5c9fd91. Not yet wired: pump + hooks.)
      control connection + one relay UDP socket, refcounted, generation-guarded, idle-
      reaped at 30s, pumped by a DEDICATED io_context on its own detached thread (never
      `client.hpp`'s context: it parks when the injector is lost, i.e. exactly when the
      tunnel matters); keying by relay socket makes proxy-side rebind a non-issue and the
      app's local UDP endpoint is documented as NOT preserved. Caps not TTLs: 32
      associations / 256 rows / 64 datagrams + 1 MiB per socket, evict-LRU + quarantine.
      Implemented as pure modules 8053eae (state) + S3 (associate call) with S5/S6 to wire.)
- [ ] Hook outbound datagrams: encapsulate and forward via the relay.
- [ ] Hook inbound datagrams: decapsulate replies and hand them to the application.
- [ ] Handle exclusions: localhost targets and proxy-loop prevention for the relay
      traffic itself.
- [ ] Report UDP activity through the existing log pipeline.
- [ ] E2E test against a UDP-capable socks5 server; keep the TCP path regression-free.

### P8 — Product / UX
- [x] Surface the CLI-only `-w/--new-console-window` as a GUI toggle (the last
      GUI/CLI parity gap; the GUI already covers all six input modes and
      proxy/log/subprocess toggles per `make_controls`). (2a63f95: check_box on the
      exec row, default OFF = byte-identical flags; `cl /Zs` probe over the exact
      vcxproj include set reports 0 diagnostics — link-unverified locally, and note
      GitHub Actions has never run on this fork, so the probe is the only signal.)
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
