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

#include "hook.hpp"
#include <utils.hpp>
#include <chrono>
#include <thread>
#include <vector>

// The injector publishes the control port plus a per-injection token in a
// per-process named mapping.  A missing mapping or a failed view is reported
// as the zero payload (port 0, empty token) rather than a null dereference in
// a victim.
//
// One read is not enough, because "not there yet" is not evidence of "never":
// injector::inject() creates the mapping from a FUNCTION-LOCAL handle
// (injector.hpp:121), so its destructor can take the name away before or
// while our reader opens it -- on a loaded machine, before the client thread
// has even been scheduled.  So the bootstrap tries again on a bounded budget:
// about five seconds, one sleep in front of every retry, which is also how
// long the injector is willing to wait for its remote LoadLibraryW to finish
// (injector.hpp:170).  Holding that mapping for the whole session instead
// belongs to the injector (M1-b); that is what makes a late read possible at
// all, and this is what makes losing the race survivable rather than fatal
// while the injector-side half is still outstanding.
constexpr int kMappingProbeTries = 20;
constexpr std::chrono::milliseconds kMappingProbeDelay{250};

port_mapping_payload get_ipc_payload() {
  handle mapping = open_mapping(get_port_mapping_name(GetCurrentProcessId()));
  if (!mapping) {
    return {};
  }

  mapped_buffer payload_buf(mapping.get());
  auto payload = payload_buf.checked<port_mapping_payload>();
  if (!payload) {
    return {};
  }

  return *payload;
}

// Retry until a port turns up or the budget runs out.  Only ever called from
// the client thread: the sleeps here must never run under the loader lock.
// Every open and every view is RAII, so a long poll cannot leak a handle even
// when the view keeps failing.
port_mapping_payload get_ipc_payload_waiting() {
  for (int attempt = 1; attempt < kMappingProbeTries; ++attempt) {
    std::this_thread::sleep_for(kMappingProbeDelay);
    if (auto payload = get_ipc_payload(); payload.port != 0) {
      return payload;
    }
  }

  return {};
}

void do_client(HINSTANCE dll_handle, port_mapping_payload ipc) {
  // C2: nothing in this file ever unmaps the module, and this is where it
  // used to happen.  By the time this thread runs, DllMain has already
  // created AND enabled the hook set, so ws2_32 jumps into code that lives
  // here, and this thread is itself executing inside the image with the CRT's
  // std::thread invoke wrapper below it on the stack.  FreeLibrary() at that
  // moment returns through freed code and leaves live detours pointing at
  // freed trampolines: an access violation in the victim on its next winsock
  // call, a far worse outcome than the un-encapsulated one this replaces.
  // P4 #5 already made the opposite choice for the mid-session case further
  // down (stay resident, never unbind the globals), so that unload was a
  // leftover contradiction.
  //
  // Who unmaps it, then?  Nobody: the OS takes the image back at process
  // exit, and DLL_PROCESS_DETACH disables the hooks on the way out.  A hooking
  // DLL has to outlive the hooks it installed.
  (void)dll_handle;

  if (ipc.port == 0) {
    ipc = get_ipc_payload_waiting(); // C2: the mapping may still be on its way
  }

  if (ipc.port == 0) {
    // No mapping within the budget: the injector never finished its setup, or
    // died trying.  Give up quietly and stay resident -- the hooks remain
    // enabled and config remains null, which is this file's documented
    // direct-passthrough state.  The host keeps talking (just not through the
    // capsule), and a broken bootstrap refuses nothing.
    return;
  }

  // The token that came with the port; the client echoes it back in its
  // introduction so the injector can tell us from a process that merely
  // guessed the mapping name (P4-3).
  const std::vector<unsigned char> token(ipc.token,
                                         ipc.token + port_mapping_token_size);

  {
    asio::io_context io_context(1);

    auto qu =
        std::make_unique<blocking_queue<InjecteeMessage>>(io_context, 1024);
    auto cfg = std::make_unique<injectee_config>();
    auto sock_map = std::make_unique<std::map<SOCKET, bool>>();

    scope_ptr_bind queue_bind(queue, qu.get());
    scope_ptr_bind config_bind(config, cfg.get());
    scope_ptr_bind map_bind(nbio_map, sock_map.get());

    injectee_client c(io_context, tcp::endpoint(localhost, ipc.port), *queue,
                      *config, token);
    asio::co_spawn(io_context, c.start(), asio::detached);

    io_context.run();

    // run() only comes back if the client could not keep any work pending,
    // i.e. after its reconnect budget expired.  Stay resident anyway:
    // unbinding the globals the hooks read would turn every later connect
    // into a silent direct connect, and unmapping the DLL while other
    // threads may be inside a detour is the use-after-free this path used to
    // cause (P4 #5).  Park instead: the hooks and the pinned routing then
    // live for as long as the victim does.
    for (;;) {
      std::this_thread::sleep_for(std::chrono::hours(1));
    }
  }
}

// Losing the injector mid-session does not unmap us, and neither does a
// bootstrap that never found the mapping -- see do_client().  The only path
// that still hands the image back is the hook-creation failure in DllMain
// below: nothing was enabled and no thread of ours was started there, so no
// part of the host can be standing inside us, and FreeLibraryAndExitThread is
// the documented way for a module to leave by itself.  Everything after
// minhook::enable() is resident for good.

BOOL WINAPI DllMain(HINSTANCE dll_handle, DWORD reason, LPVOID reserved) {
  switch (reason) {
  case DLL_PROCESS_ATTACH:
    DisableThreadLibraryCalls(dll_handle);
    minhook::init();

    if (hook_create_all().error()) {
      // a half-initialized hook set must never go live: no enable, no
      // client thread - unload the DLL again from a helper thread
      std::thread([dll_handle] {
        FreeLibraryAndExitThread(dll_handle, 0);
      }).detach();
      break;
    }

    minhook::enable();
    // The FIRST mapping read is deliberately still taken here, inline, while
    // the injector's handle to the section is certain to be alive: this runs
    // under the loader lock inside the remote LoadLibraryW, and the name can
    // be gone before any thread of ours is scheduled.  One non-blocking
    // OpenFileMapping plus MapViewOfFile is all it costs DllMain -- no sleep,
    // which is exactly why the retry does not belong here.  Everything after
    // this belongs to do_client(): the backoff, and the answer to port 0,
    // which is stay resident and inert, never unload.
    std::thread(do_client, dll_handle, get_ipc_payload()).detach();
    break;

  case DLL_PROCESS_DETACH:
    minhook::disable();
    minhook::deinit();
    hook_cleanup_wsa();
    break;
  }
  return TRUE;
}
