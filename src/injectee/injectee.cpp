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
#include <vector>

void do_client(HINSTANCE dll_handle, const port_mapping_payload &ipc) {
  if (ipc.port == 0) { // no IPC port: never start the client, just unload
    FreeLibrary(dll_handle);
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
  }
  FreeLibrary(dll_handle);
}

// The injector publishes the control port plus a per-injection token in a
// per-process named mapping.  A missing mapping or a failed view means the
// setup was broken: hand back the zero payload (port 0, empty token) and let
// the caller unload us, rather than dereferencing null in a victim.
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
