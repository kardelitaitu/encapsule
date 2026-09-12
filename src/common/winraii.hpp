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

#ifndef ENCAPSULE_COMMON_WINRAII
#define ENCAPSULE_COMMON_WINRAII

#include "tlhelp32.h"
#include "utils.hpp"
#include <Windows.h>
#include <sddl.h>
#include <atomic>
#include <cctype>
#include <memory>
#include <optional>
#include <set>
#include <vector>

template <auto f> struct static_function {
  template <typename T> decltype(auto) operator()(T &&x) const {
    return f(std::forward<T>(x));
  }
};

struct handle : std::unique_ptr<void, static_function<CloseHandle>> {
  using base_type = std::unique_ptr<void, static_function<CloseHandle>>;

  using base_type::base_type;

  handle(HANDLE hd) : base_type(hd) {}
};

struct virtual_memory {
  void *const proc_handle;
  void *mem_addr; // nulled by free(), dtor is then a no-op
  const SIZE_T size_;

  virtual_memory(void *proc_handle, SIZE_T size)
      : proc_handle(proc_handle),
        mem_addr(VirtualAllocEx(proc_handle, nullptr, size,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)),
        size_(size) {}

  virtual_memory(const virtual_memory &) = delete;
  virtual_memory(virtual_memory &&) = default;

  ~virtual_memory() { free(); }

  // Release the remote allocation before this object goes out of scope;
  // safe to call more than once.
  void free() {
    if (mem_addr) {
      VirtualFreeEx(proc_handle, mem_addr, 0, MEM_RELEASE);
      mem_addr = nullptr;
    }
  }

  operator bool() const { return mem_addr != nullptr; }

  void *get() const { return mem_addr; }

  void *process_handle() const { return proc_handle; }

  SIZE_T size() const { return size_; }

  std::optional<SIZE_T> write(const void *buf, SIZE_T n) const {
    SIZE_T written_size;

    if (WriteProcessMemory(proc_handle, mem_addr, buf, n, &written_size)) {
      return written_size;
    }

    return std::nullopt;
  }

  auto write(const void *buf) { return write(buf, size_); }

  std::optional<SIZE_T> read(void *buf, SIZE_T n) const {
    SIZE_T read_size;

    if (ReadProcessMemory(proc_handle, mem_addr, buf, n, &read_size)) {
      return read_size;
    }

    return std::nullopt;
  }

  auto read(void *buf) { return read(buf, size_); }
};

HMODULE get_current_module() {
  HMODULE mod = nullptr;

  GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                     (LPCTSTR)get_current_module, &mod);

  return mod;
}

std::wstring get_current_filename() {
  wchar_t path[1024 + 1] = {};

  GetModuleFileNameW(get_current_module(), path, 1024);

  return path;
}

// Binds a pointer that OTHER threads read, for the lifetime of this scope.
//
// The injectee's winsock detours run on the victim's threads while its client
// thread binds and retires the globals they consult, so a bind is a
// cross-thread handoff.  A plain assignment publishes the pointer with no
// ordering at all -- the compiler may sink the initialisation of *bind below
// the store -- and a plain nulling races with a reader that has already tested
// it.  Both ends are ordered here: release on publish, release on retire, and
// the reader takes the value once through load_scope() below (acquire).
//
// The least invasive shape on purpose: the slot stays a plain 'T *'.  Making it
// std::atomic<T *> instead would retype every scope-bound global and rewrite
// every '->' and 'if (ptr)' that reads one -- including on the injector side,
// which shares this header -- to buy what std::atomic_ref (C++20) buys without
// touching the object's type at all.
//
// What atomic_ref does demand is an address aligned for an atomic pointer
// access, and MSVC only checks that in Debug: its conformance test is
// _STL_ASSERT, which disappears under NDEBUG, where what is left is
// _Analysis_assume_ -- the optimiser is TOLD to assume the alignment.  So the
// check that actually fires is the static_assert below, not a comment and not
// the alignas(void *) the declarations carry: that spells the natural
// alignment of a pointer (8 on x64, 4 on x86, which is exactly
// std::atomic_ref<T *>::required_alignment) and so documents intent without
// enforcing anything a reshuffle could not break.
template <typename T> struct scope_ptr_bind {
  static_assert(alignof(T *) >= std::atomic_ref<T *>::required_alignment,
                "atomic_ref needs the slot aligned for an atomic pointer "
                "access; MSVC does not check that in Release");

  T *&ptr;

  scope_ptr_bind(T *&ptr, T *bind) : ptr(ptr) {
    std::atomic_ref<T *>(this->ptr).store(bind, std::memory_order_release);
  }

  ~scope_ptr_bind() {
    std::atomic_ref<T *>(ptr).store(nullptr, std::memory_order_release);
  }
};

// Read a scope-bound pointer exactly once, with the acquire that pairs with
// scope_ptr_bind's release.  Hold the result in a local and use the local:
//
//   if (auto *cfg = load_scope(config); cfg) { cfg->get(); }  // one read
//   if (config) { config->get(); }                            // two reads
//
// The second spelling is the C4 window: it is not one value but two, and the
// compiler is free to reload the global after the test (MSVC does as soon as
// any call -- even a std::mutex constructor -- sits between the two) while the
// thread owning the scope retires it in between.  A scratch two-thread harness
// on this toolchain counted that re-read coming back null 1094 times out of
// 44045 uses in three seconds -- the null dereference of a pointer a detour had
// just checked, inside a victim.  The in-tree pin of the property is
// tests/utils/utils_test.cpp, a_racing_read_uses_the_one_value_it_tested.
//
// What the release/acquire pair buys is two things and only two: a read is ONE
// atomic read, so the value tested is the value used, and publication is
// ORDERED, so a reader that acquires the pointer also sees what the binder
// wrote before storing it.  Neither is a lifetime guarantee -- acquire does not
// keep the object alive.  The objects behind these pointers outlive every
// detour that can see them because of residency: do_client() parks instead of
// unwinding and this module never unmaps itself (C2, P4 #5).  do_client() also
// declares its binds after the owners, so a retirement nulls the slots before
// it frees them, which narrows that window and does not close it.  Nobody
// should re-introduce an unbind-on-some-path and treat acquire as having made
// it safe: the guarantee is the park, not the memory order.
template <typename T> T *load_scope(T *&ptr) {
  static_assert(alignof(T *) >= std::atomic_ref<T *>::required_alignment,
                "atomic_ref needs the slot aligned for an atomic pointer "
                "access; MSVC does not check that in Release");
  return std::atomic_ref<T *>(ptr).load(std::memory_order_acquire);
}

template <typename F> void match_process(F &&f) {
  if (handle snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL)) {
    PROCESSENTRY32W entry = {sizeof(PROCESSENTRY32W)};
    if (Process32FirstW(snapshot.get(), &entry)) {
      do {
        std::forward<F>(f)(entry);
      } while (Process32NextW(snapshot.get(), &entry));
    }
  }
}

// Owns memory handed out by the advapi32 SDDL helpers (ConvertSidToStringSidW,
// ConvertStringSecurityDescriptorToSecurityDescriptorW), both LocalFree-based.
struct local_memory
    : std::unique_ptr<void, static_function<LocalFree>> {
  using base_type = std::unique_ptr<void, static_function<LocalFree>>;

  local_memory(void *p) : base_type(p) {}
};

// The mapping carries the control port from the injector to the injectee, so
// it must not inherit the default (NULL) DACL that would let any other process
// in the session read or rewrite it. The descriptor below grants generic all
// to SYSTEM and to the current user only, and is SACL-protected (D:P).
//
// FAIL CLOSED: if any step of building the descriptor fails, the mapping is
// NOT created with default security - create_mapping reports the same failure
// a rejected CreateFileMappingW would, and the injection is refused.
inline handle create_mapping(const std::wstring &name, DWORD buf_size) {
  const HANDLE failed = nullptr; // what a failed CreateFileMappingW yields

  HANDLE raw_token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) {
    return failed;
  }
  handle token = raw_token;

  DWORD needed = 0;
  GetTokenInformation(token.get(), TokenUser, nullptr, 0, &needed);
  if (needed < sizeof(TOKEN_USER)) {
    return failed;
  }

  auto buffer = std::make_unique<char[]>(needed);
  if (!GetTokenInformation(token.get(), TokenUser, buffer.get(), needed,
                           &needed)) {
    return failed;
  }
  auto *user = reinterpret_cast<TOKEN_USER *>(buffer.get());

  LPWSTR sid_text = nullptr;
  if (!ConvertSidToStringSidW(user->User.Sid, &sid_text)) {
    return failed;
  }
  local_memory sid_owner = sid_text;

  std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;";
  sddl += sid_text;
  sddl += L")";

  PSECURITY_DESCRIPTOR sd = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
    return failed;
  }
  local_memory sd_owner = sd; // must outlive the CreateFileMappingW call

  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = sd;
  sa.bInheritHandle = FALSE;

  return CreateFileMappingW(INVALID_HANDLE_VALUE, // use paging file
                            &sa, // explicit DACL, never a NULL DACL
                            PAGE_READWRITE,       // read/write access
                            0,        // maximum object size (high-order DWORD)
                            buf_size, // maximum object size (low-order DWORD)
                            name.c_str()); // name of mapping object
}

inline handle open_mapping(const std::wstring &name) {
  return OpenFileMappingW(FILE_MAP_ALL_ACCESS, // read/write access
                          FALSE,               // do not inherit the name
                          name.c_str());       // name of mapping object
}

struct mapped_buffer : std::unique_ptr<void, static_function<UnmapViewOfFile>> {
  using base_type = std::unique_ptr<void, static_function<UnmapViewOfFile>>;

  mapped_buffer(HANDLE mapping, DWORD offset = 0, SIZE_T size = 0)
      : base_type(MapViewOfFile(mapping,             // handle to map object
                                FILE_MAP_ALL_ACCESS, // read/write permission
                                0, offset, size)) {}

  // Typed access to the view: nullptr when the mapping or the view itself
  // failed, so callers check once instead of dereferencing .get() blindly.
  template <typename T> T *checked() const {
    return get() ? (T *)get() : nullptr;
  }
};

inline std::optional<std::wstring> get_process_filepath(DWORD pid) {
  handle process =
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

  DWORD size = MAX_PATH;
  auto filename = std::make_unique<wchar_t[]>(size);
  if (!QueryFullProcessImageNameW(process.get(), 0, filename.get(), &size)) {
    return std::nullopt;
  }

  return std::wstring(filename.get(), size);
}

inline auto get_process_name(DWORD pid) {
  std::wstring result;
  match_process([pid, &result](const PROCESSENTRY32W &entry) {
    if (pid == entry.th32ProcessID) {
      result = entry.szExeFile;
    }
  });

  std::string res_u8 = utf8_encode(result);
  if (res_u8.ends_with(".exe")) {
    return res_u8.substr(0, res_u8.size() - 4);
  }
  return res_u8;
}

template <typename F> void match_process_by_name(F &&f) {
  match_process([&f](const PROCESSENTRY32W &entry) {
    std::string name_u8 = utf8_encode(entry.szExeFile);
    if (name_u8.ends_with(".exe")) {
      auto name = name_u8.substr(0, name_u8.size() - 4);
      std::forward<F>(f)(name, entry.th32ProcessID);
    }
  });
}

template <typename F> void match_process_by_path(F &&f) {
  match_process([&f](const PROCESSENTRY32W &entry) {
    if (auto wpath = get_process_filepath(entry.th32ProcessID)) {
      auto path = utf8_encode(*wpath);
      std::forward<F>(f)(path, entry.th32ProcessID);
    }
  });
}

template <typename F> void enumerate_child_pids(DWORD pid, F &&f) {
  match_process([pid, &f](const PROCESSENTRY32W &entry) {
    if (pid == entry.th32ParentProcessID) {
      std::forward<F>(f)(entry.th32ProcessID);
    }
  });
}

// Every pid alive right now, in Toolhelp32 snapshot order. Walks the same
// snapshot as match_process, so there is exactly one enumeration to keep
// correct; an empty result means the snapshot itself could not be taken.
inline std::vector<DWORD> enumerate_pids() {
  std::vector<DWORD> pids;
  match_process([&pids](const PROCESSENTRY32W &entry) {
    pids.push_back(entry.th32ProcessID);
  });

  return pids;
}

// The pure half of watch mode: which pids appeared since the previous poll.
// No syscalls here -- the caller owns the snapshots -- so the rule itself is
// host-testable.  The result is ascending and duplicate-free: a pid listed
// twice in `now` is one process, and anything already in `prev` is not new.
// A pid that exited and shows up again later IS reported again: the caller
// stores the poll that proved the exit, so the number is no longer in `prev`.
inline std::vector<DWORD> process_watch_diff(const std::set<DWORD> &prev,
                                             const std::vector<DWORD> &now) {
  const std::set<DWORD> current(now.begin(), now.end()); // sorts and dedups

  std::vector<DWORD> added;
  for (DWORD pid : current) {
    if (!prev.contains(pid)) {
      added.push_back(pid);
    }
  }

  return added;
}

// The short name of a live process -- image basename, lowercased, without the
// ".exe" -- or std::nullopt when the process has already exited or cannot be
// opened.  Races are the norm for a watcher: callers MUST tolerate nullopt and
// just skip that pid, never treat it as a match.  Matching a name against a
// pattern is left to match_process_by_name / filename_wildcard_match, so no
// second copy of that rule lives here.
inline std::optional<std::string> process_short_name(DWORD pid) {
  auto wpath = get_process_filepath(pid);
  if (!wpath) {
    return std::nullopt;
  }

  auto filename = wpath->substr(wpath->find_last_of(L"\\/") + 1);
  auto name = utf8_encode(filename);

  // ASCII folding only: bytes >= 0x80 are UTF-8 tails and pass through, so a
  // non-ASCII image name survives unchanged apart from its ASCII letters.
  for (char &c : name) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }

  if (name.ends_with(".exe")) {
    name = name.substr(0, name.size() - 4);
  }

  return name;
}

inline std::optional<PROCESS_INFORMATION>
create_process(const std::wstring &command, DWORD creation_flags = 0) {
  STARTUPINFO startup_info{};
  PROCESS_INFORMATION process_info{};
  if (CreateProcessW(nullptr, std::wstring{command}.data(), nullptr, nullptr,
                     false, creation_flags, nullptr, nullptr, &startup_info,
                     &process_info) == 0) {
    return std::nullopt;
  }

  return process_info;
}

inline std::optional<PROCESS_INFORMATION>
create_process(const std::string &path, DWORD creation_flags = 0) {
  auto wpath = utf8_decode(path);
  return create_process(wpath, creation_flags);
}

#endif
