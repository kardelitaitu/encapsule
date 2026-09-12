# Copyright 2022 PragmaTwice
#
# Licensed under the Apache License,
# Version 2.0(the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# src/injector/server.hpp is the code that runs in the tool's own process, so
# this target links what encapsule-cli links: asio (standalone) plus the common
# schema.  No socket is opened by server_test.cpp -- it pins the two policies
# (the kept-bootstrap record and the lost-vs-retired ending) through the same
# functions the session calls, so this stays a unit test and the blocking
# ctest -E "^e2e\." step in build.yml picks it up by name alone.

add_executable(encapsule_test_server server_test.cpp)
target_link_libraries(encapsule_test_server PRIVATE encapsule_common protopuf
		ws2_32)
target_include_directories(encapsule_test_server PRIVATE
		${CMAKE_SOURCE_DIR}/tests ${CMAKE_SOURCE_DIR}/src/injector
		${asio_SOURCE_DIR}/asio/include)
# 4097 map inserts per capped scenario, twice over: well under a second.
add_test(NAME common.server COMMAND encapsule_test_server)
set_tests_properties(common.server PROPERTIES TIMEOUT 60)
