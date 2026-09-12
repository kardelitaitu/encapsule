// Copyright 2022 PragmaTwice
//
// Licensed under the Apache License,
// Version 2.0(the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ENCAPSULE_INJECTOR_INJECTOR
#define ENCAPSULE_INJECTOR_INJECTOR

#include "utils.hpp"
#include "winraii.hpp"
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <string_view>
#include <tlhelp32.h>
#include <vector>

namespace fs = std::filesystem;

struct injector {
  static inline const FARPROC load_library =
      GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");

#if defined(_WIN64)
  static inline const char wow64_address_dumper_filename[] =
      "wow64-address-dumper.exe";

  static std::optional<FARPROC> get_wow64_load_library() {
    auto path = fs::path(get_current_filename())
                    .replace_filename(wow64_address_dumper_filename);

    if (!std::filesystem::exists(path)) {
      return std::nullopt;
    }

    auto pi = create_process(path.wstring(), CREATE_NO_WINDOW);
    if (!pi) {
      return std::nullopt;
    }

    WaitForSingleObject(pi->hProcess, INFINITE);

    DWORD ec = 0;
    if (!GetExitCodeProcess(pi->hProcess, &ec)) {
      return std::nullopt;
    }

    return reinterpret_cast<FARPROC>((uint64_t)ec);
  }

  static inline const FARPROC load_library_wow64 =
      get_wow64_load_library().value_or(nullptr);
#endif

  // Per-injection tokens (P4-3).  inject() mints a random token, writes it
  // into the mapping next to the control port and records it here; the control
  // server looks it up when an injectee introduces itself, so guessing the
  // mapping name (it only embeds a pid) no longer buys a control channel.
  using injection_token = std::vector<unsigned char>;

  inline static std::mutex token_mutex;
  inline static std::map<DWORD, injection_token> tokens;

  // The published mappings themselves, kept for the injector's whole lifetime
  // (M1-b).  A named section's NAME exists only while some handle to it is
  // open, so this map is not a cache and not a convenience: it is the reason
  // an injectee can still find the bootstrap after inject() has returned.  See
  // the two facts at the head of publish().
  //
  // Same mutex as the tokens, on purpose, and one invariant with it: a pid is
  // in `tokens` exactly when it is in `mappings`.  The two records are the two
  // halves of one publish, and either alone is a half-injection -- a name
  // nobody can authenticate against, or a token pointing at a section that is
  // already gone.  Both maps are therefore written in one critical section and
  // erased in one, and the lock covers only a map operation and the
  // CloseHandle it releases: nothing here blocks, waits or co_awaits.
  inline static std::map<DWORD, handle> mappings;

  static void remember_token(DWORD pid, const injection_token &token) {
    std::lock_guard guard(token_mutex);
    tokens[pid] = token;
  }

  // Retires a bootstrap by pid: the token the server checks, and the handle
  // that keeps the section's name alive.  This is what a lost session leaves
  // behind (server.hpp's remove() calls it from stop()), and it is
  // deliberately total -- an injectee reads its mapping once, at attach, so a
  // session that is gone could not be handed a new port and token either way.
  static void forget_token(DWORD pid) {
    std::lock_guard guard(token_mutex);
    tokens.erase(pid);
    mappings.erase(pid); // the CloseHandle that takes the name out
  }

  // The rollback for a publish whose load failed, and the reason publish
  // returns the token: erase only what THIS publish recorded.  A re-injection
  // of the same pid, or two threads that raced past the server's contains()
  // check, has already overwritten both records, and erasing by pid alone
  // would then retire a bootstrap some live capsule is using.  Returns
  // whether it did anything, so a caller can tell a rollback from a no-op.
  static bool forget_bootstrap(DWORD pid, const injection_token &token) {
    std::lock_guard guard(token_mutex);

    auto iter = tokens.find(pid);
    if (iter == tokens.end() || !(iter->second == token)) {
      return false;
    }

    tokens.erase(iter);
    mappings.erase(pid);
    return true;
  }

  // Fail-closed: a missing field, a pid nobody injected, a different length or
  // one different byte all refuse the session.
  template <typename Presented>
  static bool token_matches(DWORD pid, const Presented &presented) {
    if (!presented.has_value()) {
      return false;
    }

    std::lock_guard guard(token_mutex);
    auto iter = tokens.find(pid);
    if (iter == tokens.end()) {
      return false;
    }

    const injection_token &expected = iter->second;
    const auto &got = *presented;
    return expected.size() == got.size() &&
           std::equal(expected.begin(), expected.end(), got.begin(),
                      [](unsigned char a, auto b) {
                        return a == static_cast<unsigned char>(b);
                      });
  }

  static injection_token token_of(const port_mapping_payload &payload) {
    return injection_token(payload.token,
                           payload.token + port_mapping_token_size);
  }

  // --------------------------------------------------------------- publish --

  // Step one of an injection: put the bootstrap in the namespace and
  // remember what is in it.  Step two is load_into(), the remote load; inject
  // below is the two, in that order.  Two facts belong at the head of this
  // function, because a reader who does not know them will undo both:
  //
  //   1. A named section's NAME lives only while some handle to it stays
  //      open.  Until now the handle was a local of inject(), so the
  //      CloseHandle in its destructor retired the name on the way OUT of a
  //      successful injection -- an injectee that had not mapped the payload
  //      by then could never find it again.  No amount of retrying on the
  //      injectee side recovers that; it was built and measured, and
  //      e2e.inject_connect came back with 0 CONNECTs and the decoy still
  //      running.  So the handle moves into `mappings` and is held for the
  //      injector's whole lifetime.  Do not localise it again.
  //
  //   2. A resident injectee reads this mapping exactly once, at attach.  It
  //      has no channel to be handed a new port and token, so re-publishing
  //      under the same name reaches nobody already loaded: holding the name
  //      here is the precondition for reconnecting a capsule, not the whole
  //      answer.  That answer -- the server-side adopt / publish-without-load
  //      step -- is M1-d's, which is why publish() is split out and exposed
  //      and why it hands the token back to its caller.
  //
  // Returns the published token so the caller can roll the publish back by
  // identity (forget_bootstrap) if its load fails; null on a failure that
  // recorded nothing and left nothing open.
  static std::optional<injection_token> publish(DWORD pid,
                                               std::uint16_t port) {
    // No RNG, no token: refuse the injection rather than publish a payload
    // whose "secret" is whatever the zero-initialised struct holds.
    auto payload = get_port_mapping_payload(port);
    if (!payload) {
      return std::nullopt;
    }

    handle mapping = create_mapping(get_port_mapping_name(pid),
                                    (DWORD)get_port_mapping_payload_size());
    if (!mapping) {
      return std::nullopt;
    }

    mapped_buffer payload_buf(mapping.get());
    auto payload_dst = payload_buf.checked<port_mapping_payload>();
    if (!payload_dst) {
      return std::nullopt; // the handle is still a local: it goes back here
    }
    *payload_dst = *payload;

    auto token = token_of(*payload);
    {
      std::lock_guard guard(token_mutex);
      // What remember_token() used to be handed, written here instead so that
      // the token and the mapping that describe one publish land in one
      // critical section (the invariant on `mappings`).  Still before any
      // remote thread exists -- load_into() is the next call -- so an injectee
      // can never introduce itself ahead of the token it has to present.
      tokens[pid] = token;
      mappings.insert_or_assign(pid, std::move(mapping));
    }

    return token;
  }

  // Step two: load the capsule into a process that already has step one.
  // Every word of the remote sequence is what inject() used to do inline --
  // the allocation, the write, the choice of LoadLibraryW for the target's
  // bitness, the 5-second cap that keeps a wedged target from hanging the
  // injector, and the exit-code read that tells a refused DLL from a loaded
  // one.  Every failure un-does the publish, token AND mapping.
  static bool load_into(DWORD pid, HANDLE proc, const injection_token &token,
                        BOOL isWoW64, std::wstring_view filename) {
    virtual_memory mem(proc, (filename.size() + 1) * sizeof(wchar_t));
    if (!mem) {
      forget_bootstrap(pid, token);
      return false;
    }

    if (!mem.write(filename.data())) {
      forget_bootstrap(pid, token);
      return false;
    }

    FARPROC current_load_library =
#if defined(_WIN64)
        isWoW64 ? load_library_wow64 : load_library;
#else
        load_library;
#endif
    if (!current_load_library) {
      forget_bootstrap(pid, token);
      return false;
    }

    handle thread = CreateRemoteThread(
        proc, nullptr, 0, (LPTHREAD_START_ROUTINE)current_load_library,
        mem.get(), 0, nullptr);
    if (!thread) {
      forget_bootstrap(pid, token);
      return false;
    }

    // A remote thread that never finishes means LoadLibraryW is wedged in
    // the target: never hang the injector, and give back the allocation.
    if (WaitForSingleObject(thread.get(), 5000) != WAIT_OBJECT_0) {
      mem.free();
      forget_bootstrap(pid, token);
      return false;
    }

    // The thread exit code is the HMODULE LoadLibraryW returned in the
    // target. NULL means it did not load (wrong arch, blocked DLL, missing
    // dependency) - which used to be reported to the user as a success.
    DWORD module_handle = 0;
    if (!GetExitCodeThread(thread.get(), &module_handle) ||
        module_handle == 0) {
      mem.free();
      forget_bootstrap(pid, token);
      return false;
    }

    return true;
  }

  // Both halves, in order: publish, then load, and a load that fails takes
  // the publish with it.  The success path is what it always was -- mapping
  // created, payload written, token recorded before the thread, the remote
  // LoadLibraryW waited for and its exit code read -- with one addition: the
  // mapping handle now stays open in `mappings` after this returns true.
  static bool inject(DWORD pid, HANDLE proc, std::uint16_t port, BOOL isWoW64,
                     std::wstring_view filename) {
    auto token = publish(pid, port);
    if (!token) {
      return false;
    }

    return load_into(pid, proc, *token, isWoW64, filename);
  }

  static inline const char injectee_filename[] = "encapsule-injectee.dll";
  static inline const char injectee_wow64_filename[] =
      "encapsule-injectee32.dll";

  static std::optional<std::wstring>
  find_injectee(std::wstring_view self_binary_path, BOOL isWoW64) {
    auto path = fs::path(self_binary_path)
                    .replace_filename(isWoW64 ? injectee_wow64_filename
                                              : injectee_filename);

    if (!std::filesystem::exists(path)) {
      return std::nullopt;
    }

    return path.wstring();
  }

  // Case-insensitive compare of one NUL-terminated Toolhelp name against one
  // of the two injectee literals above.  ASCII folding only, the same rule
  // process_short_name() uses, so a name outside ASCII can merely fail to
  // match, and no CRT case helper, code page or temporary sits on the way.
  // The length comes from the string_view, so the narrow side is never read
  // past its own end and the wide side must stop exactly where it does.
  static bool module_name_matches(const wchar_t *module,
                                  std::string_view expected) {
    auto fold = [](wchar_t c) {
      return (c >= L'A' && c <= L'Z') ? wchar_t(c + (L'a' - L'A')) : c;
    };

    std::size_t i = 0;
    for (; i < expected.size(); ++i) {
      if (fold(module[i]) !=
          fold(static_cast<wchar_t>(static_cast<unsigned char>(expected[i])))) {
        return false;
      }
    }

    return module[i] == 0; // the toolhelp name holds nothing extra
  }

  // Does this entry name our capsule?  Asked twice: szModule is documented as
  // a base name WITHOUT its extension, while the file the remote LoadLibraryW
  // was handed certainly has one.  Whichever spelling the snapshot uses it
  // names the same loaded module, and matching only one of them would leave
  // the message to chance.  Both literals above end in '.dll', so the second
  // spelling is always the stem -- and only the stem, so some other
  // 'encapsule-injectee.<ext>' is not mistaken for ours.
  static bool module_is_ours(const wchar_t *module, std::string_view name) {
    if (module_name_matches(module, name)) {
      return true;
    }

    static constexpr std::string_view extension = ".dll";
    if (!name.ends_with(extension)) {
      return false;
    }

    return module_name_matches(module,
                               name.substr(0, name.size() - extension.size()));
  }

  // -------------------------------------------------- already encapsulated? --
  //
  // Best-effort answer to: is an encapsule capsule already mapped into pid?
  //
  // Why the question needs asking.  7593252 took away the injectee's
  // self-FreeLibrary, so a capsule that has once loaded stays resident for the
  // life of the target, and LoadLibraryW on a module that is already mapped
  // does NOT run DllMain again -- it bumps the refcount and returns the SAME
  // HMODULE.  load_into() reads that HMODULE as the remote thread's exit code
  // and calls any nonzero value a success, so a second inject() into the same
  // pid reports a fresh injection that attached nothing: no new DllMain, no
  // new client thread, and nobody left to read the token publish() has just
  // written.  This is what lets the caller say 'already encapsulated' instead.
  //
  // UI TRUTH, NOT A SECURITY GATE.  Everything here runs against a process a
  // same-user attacker owns and can arrange to misreport: the snapshot can be
  // refused outright, can come back short, or can be made to carry a name that
  // merely looks like ours.  NOTHING may be authorized, permitted, refused or
  // gated on this answer, and it is never compared with a token.
  // Authentication stays exactly where it was, in token_matches() and in the
  // mapping DACL.  The most a wrong answer can do is print one inaccurate
  // sentence -- which is the same thing the phantom re-injection it replaces
  // costs today, and less than it costs the user.
  //
  // Every way of NOT knowing returns false: a rejected snapshot, a pid that
  // has already exited, a 32-bit module list this tool cannot enumerate.
  // false is also the answer for a process that was never encapsulated, which
  // is why callers read it as 'say what you used to say'.  Degrading to
  // today's message is the designed failure mode: no path through here blocks,
  // throws, writes to the target, or refuses an injection.
  static bool module_resident(DWORD pid, bool is_wow64) {
    const std::string_view name =
        is_wow64 ? injectee_wow64_filename : injectee_filename;

    // TH32CS_SNAPMODULE32 is what makes a WoW64 target's 32-bit list visible
    // to a 64-bit tool.  Without it every 32-bit target answers false and the
    // message stays a lie, which is the only thing this helper is for.
    const DWORD flags =
        TH32CS_SNAPMODULE | (is_wow64 ? TH32CS_SNAPMODULE32 : 0);

    // Toolhelp reports failure as INVALID_HANDLE_VALUE, not NULL, so the raw
    // handle is tested before the wrapper takes it on: handing -1 to
    // CloseHandle would be a call about something that was never a handle.
    const HANDLE raw = CreateToolhelp32Snapshot(flags, pid);
    if (raw == INVALID_HANDLE_VALUE) {
      return false;
    }
    handle snapshot(raw);

    MODULEENTRY32W entry = {sizeof(MODULEENTRY32W)};
    if (!Module32FirstW(snapshot.get(), &entry)) {
      return false; // nothing enumerable is not proof of absence
    }

    do {
      if (module_is_ours(entry.szModule, name)) {
        return true;
      }
    } while (Module32NextW(snapshot.get(), &entry));

    return false;
  }

  // The entry point both front ends call.  Its bool is exactly what it has
  // always been: publish and load succeeded, or did not.  It cannot also carry
  // the new distinction, and it does not try to -- a re-injection of a
  // resident capsule really does succeed at the Win32 level, so turning this
  // bool into an enum or a struct would be a change every caller has to make,
  // and 'attaching' versus 'already encapsulated' would arrive as a compile
  // error in the front ends instead of as a better sentence.
  //
  // So the distinction is additive: hand it a bool and it receives whether the
  // capsule was ALREADY mapped before this call, i.e. which of the two words
  // is true.  Pass nothing, as every caller does today, and this is the old
  // call with the old behaviour, byte for byte.
  //
  //    bool resident = false;
  //    if (injector::inject(pid, port, &resident)) {
  //      info(resident ? "{}: already encapsulated" : "{}: injected", pid);
  //    }
  //
  // The out value is defined on every exit, the failures included, and it is
  // filled BEFORE publish/load -- after a load the module is of course
  // resident, so this is the last moment at which the answer says whether THIS
  // call is the one that attached.  Nothing on this path is refused, skipped
  // or reordered because of it: module_resident() reports, it does not gate.
  static bool inject(DWORD pid, std::uint16_t port,
                     bool *already_encapsulated = nullptr) {
    if (already_encapsulated) {
      *already_encapsulated = false; // defined on every path out of here
    }

    handle proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc)
      return false;

    BOOL isWoW64 = false;
#if defined(_WIN64)
    if (!IsWow64Process(proc.get(), &isWoW64)) {
      return false;
    }
#endif

    if (already_encapsulated) {
      *already_encapsulated = module_resident(pid, isWoW64 != FALSE);
    }

    if (auto path = find_injectee(get_current_filename(), isWoW64)) {
      return inject(pid, proc.get(), port, isWoW64, path.value());
    }

    return false;
  }

  template <typename F>
  static void pid_by_name_wildcard(const std::string &name, F &&f) {
    match_process_by_name([name, &f](const std::string &pname, DWORD pid) {
      if (filename_wildcard_match(name.data(), pname.data())) {
        std::forward<F>(f)(pid);
      }
    });
  }

  template <typename F>
  static void pid_by_name_regex(const std::string &name, F &&f) {
    match_process_by_name([name, &f](const std::string &pname, DWORD pid) {
      if (regex_match_filename(name, pname)) {
        std::forward<F>(f)(pid);
      }
    });
  }

  template <typename F>
  static void pid_by_path_wildcard(const std::string &path, F &&f) {
    match_process_by_path([path, &f](const std::string &ppath, DWORD pid) {
      if (filename_wildcard_match(path.data(), ppath.data())) {
        std::forward<F>(f)(pid);
      }
    });
  }

  template <typename F>
  static void pid_by_path_regex(const std::string &path, F &&f) {
    match_process_by_path([path, &f](const std::string &ppath, DWORD pid) {
      if (regex_match_filename(path, ppath)) {
        std::forward<F>(f)(pid);
      }
    });
  }
};

#endif
