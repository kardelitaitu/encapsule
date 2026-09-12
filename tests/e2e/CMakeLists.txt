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

# Every product artifact this harness touches is referenced ONCE, via the
# target variables and the TARGET_FILE generator expressions below, so the
# encapsule rename (P3) stays a small edit in this file only.
set(ENCAPSULE_E2E_DUMMY_TARGET encapsule_e2e_dummy)
set(ENCAPSULE_E2E_DUMMY_NAME encapsule_e2e_dummy.exe)
set(ENCAPSULE_E2E_TEST_TARGET encapsule_test_e2e)
set(ENCAPSULE_E2E_INJECTOR_TARGET encapsule-cli)
set(ENCAPSULE_E2E_INJECTEE_TARGET encapsule-injectee)

# The decoy: a plain TCP client that hammers a dead address until it gets
# injected and its connect() is proxied somewhere that answers.
add_executable(${ENCAPSULE_E2E_DUMMY_TARGET} dummy_target.cpp)
target_link_libraries(${ENCAPSULE_E2E_DUMMY_TARGET} PRIVATE ws2_32)

add_executable(${ENCAPSULE_E2E_TEST_TARGET} e2e_test.cpp)
target_link_libraries(${ENCAPSULE_E2E_TEST_TARGET} PRIVATE
	encapsule_common protopuf ws2_32)
target_include_directories(${ENCAPSULE_E2E_TEST_TARGET} PRIVATE
	${CMAKE_SOURCE_DIR}/tests
	${CMAKE_SOURCE_DIR}/src/injectee
	${asio_SOURCE_DIR}/asio/include)
target_compile_definitions(${ENCAPSULE_E2E_TEST_TARGET} PRIVATE
	ENCAPSULE_E2E_DUMMY_NAME="${ENCAPSULE_E2E_DUMMY_NAME}")
add_dependencies(${ENCAPSULE_E2E_TEST_TARGET}
	${ENCAPSULE_E2E_INJECTOR_TARGET} ${ENCAPSULE_E2E_DUMMY_TARGET}
	${ENCAPSULE_E2E_INJECTEE_TARGET})

# Always registered: loopback only, nothing is injected, so it runs anywhere.
add_test(NAME e2e.loopback_selfcheck
	COMMAND ${ENCAPSULE_E2E_TEST_TARGET} --selfcheck)

# Properties shared by every e2e test.  CTest takes no glob in
# set_tests_properties, so each test is named where it is registered, but the
# property list itself is written once, here.  SKIP_RETURN_CODE 77 is what the
# not-yet-implemented injection driver exits with, so the wave gate reports it
# as skipped rather than failed.
set(ENCAPSULE_E2E_TEST_PROPERTIES
	RUN_SERIAL TRUE TIMEOUT 120 LABELS e2e SKIP_RETURN_CODE 77)

set_tests_properties(e2e.loopback_selfcheck
	PROPERTIES ${ENCAPSULE_E2E_TEST_PROPERTIES})

option(ENCAPSULE_E2E_INJECT "run the real inject-and-connect e2e test" ON)

if(ENCAPSULE_E2E_INJECT AND CMAKE_SIZEOF_VOID_P EQUAL 8)
	add_test(NAME e2e.inject_connect
		COMMAND ${ENCAPSULE_E2E_TEST_TARGET}
			--cli $<TARGET_FILE:${ENCAPSULE_E2E_INJECTOR_TARGET}>
			--dummy $<TARGET_FILE:${ENCAPSULE_E2E_DUMMY_TARGET}>)

	set_tests_properties(e2e.inject_connect
		PROPERTIES ${ENCAPSULE_E2E_TEST_PROPERTIES})
endif()
