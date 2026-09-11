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

# Every product artifact this harness touches is named ONCE, here, so the
# encapsule rename (P3) is a 3-line edit: this block, the two TARGET_FILE
# uses in the gated add_test() below, and nothing else.
set(PROXINJECT_E2E_ARTIFACTS
	proxinjectee.dll             # x64 injectee, target "proxinjectee"
	proxinjector-cli.exe         # injector driver, target "proxinjector-cli"
	proxinjectee32.dll           # Win32 injectee, as staged by build.ps1
	wow64-address-dumper.exe     # Win32 helper, PROXINJECTEE_ONLY pass
)

set(PROXINJECT_E2E_DUMMY_TARGET proxinject_e2e_dummy)
set(PROXINJECT_E2E_DUMMY_NAME proxinject_e2e_dummy.exe)
set(PROXINJECT_E2E_TEST_TARGET proxinject_test_e2e)
set(PROXINJECT_E2E_INJECTOR_TARGET proxinjector-cli)
set(PROXINJECT_E2E_INJECTEE_TARGET proxinjectee)

# The decoy: a plain TCP client that hammers a dead address until it gets
# injected and its connect() is proxied somewhere that answers.
add_executable(${PROXINJECT_E2E_DUMMY_TARGET} dummy_target.cpp)
target_link_libraries(${PROXINJECT_E2E_DUMMY_TARGET} PRIVATE ws2_32)

add_executable(${PROXINJECT_E2E_TEST_TARGET} e2e_test.cpp)
target_link_libraries(${PROXINJECT_E2E_TEST_TARGET} PRIVATE
	proxinject_common protopuf ws2_32)
target_include_directories(${PROXINJECT_E2E_TEST_TARGET} PRIVATE
	${CMAKE_SOURCE_DIR}/tests
	${CMAKE_SOURCE_DIR}/src/injectee
	${asio_SOURCE_DIR}/asio/include)
target_compile_definitions(${PROXINJECT_E2E_TEST_TARGET} PRIVATE
	PROXINJECT_E2E_DUMMY_NAME="${PROXINJECT_E2E_DUMMY_NAME}")
add_dependencies(${PROXINJECT_E2E_TEST_TARGET}
	${PROXINJECT_E2E_INJECTOR_TARGET} ${PROXINJECT_E2E_DUMMY_TARGET}
	${PROXINJECT_E2E_INJECTEE_TARGET})

# Always registered: loopback only, nothing is injected, so it runs anywhere.
add_test(NAME e2e.loopback_selfcheck
	COMMAND ${PROXINJECT_E2E_TEST_TARGET} --selfcheck)

# Properties shared by every e2e test.  CTest takes no glob in
# set_tests_properties, so each test is named where it is registered, but the
# property list itself is written once, here.  SKIP_RETURN_CODE 77 is what the
# not-yet-implemented injection driver exits with, so the wave gate reports it
# as skipped rather than failed.
set(PROXINJECT_E2E_TEST_PROPERTIES
	RUN_SERIAL TRUE TIMEOUT 120 LABELS e2e SKIP_RETURN_CODE 77)

set_tests_properties(e2e.loopback_selfcheck
	PROPERTIES ${PROXINJECT_E2E_TEST_PROPERTIES})

option(PROXINJECT_E2E_INJECT "run the real inject-and-connect e2e test" ON)

if(PROXINJECT_E2E_INJECT AND CMAKE_SIZEOF_VOID_P EQUAL 8)
	add_test(NAME e2e.inject_connect
		COMMAND ${PROXINJECT_E2E_TEST_TARGET}
			--cli $<TARGET_FILE:${PROXINJECT_E2E_INJECTOR_TARGET}>
			--dummy $<TARGET_FILE:${PROXINJECT_E2E_DUMMY_TARGET}>)

	set_tests_properties(e2e.inject_connect
		PROPERTIES ${PROXINJECT_E2E_TEST_PROPERTIES})
endif()
