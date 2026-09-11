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

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <WinSock2.h>
#include <Windows.h>

#include "test_support.hpp"

#include <asio/ip/address.hpp>

#include <bit>

namespace ip = asio::ip;

#include <schema.hpp>
#include <winnet.hpp>

void smoke() {
  CHECK(true);
}

int main() {
  WSADATA w;
  WSAStartup(MAKEWORD(2, 2), &w);
  RUN(smoke);
  WSACleanup();
  return test_failures;
}
