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

cmake_minimum_required(VERSION 3.20)

project(encapsule)

option(ENCAPSULE_INJECTEE_ONLY "only build encapsule-injectee" OFF)

if(NOT WIN32)
	message(FATAL_ERROR "support Windows only")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

include(FetchContent)

FetchContent_Declare(minhook
	GIT_REPOSITORY https://github.com/TsudaKageyu/minhook
	GIT_TAG 49d03ad118cf7f6768c79a8f187e14b8f2a07f94
)

set(BUILD_TESTS OFF CACHE BOOL "")
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_Declare(protopuf
	GIT_REPOSITORY https://github.com/PragmaTwice/protopuf
	GIT_TAG v2.2.1
)

FetchContent_Declare(argparse
	GIT_REPOSITORY https://github.com/p-ranav/argparse
	GIT_TAG v2.9
)

FetchContent_Declare(spdlog
	GIT_REPOSITORY https://github.com/gabime/spdlog
	GIT_TAG v1.10.0
)

FetchContent_MakeAvailable(minhook protopuf)
if(NOT ENCAPSULE_INJECTEE_ONLY)
	FetchContent_MakeAvailable(argparse spdlog)
endif()

FetchContent_Declare(asio
	GIT_REPOSITORY https://github.com/chriskohlhoff/asio
	GIT_TAG asio-1-22-2
)

FetchContent_GetProperties(asio)
if(NOT asio_POPULATED)
  FetchContent_Populate(asio)
endif()

if(NOT ENCAPSULE_INJECTEE_ONLY)
	set(ELEMENTS_ASIO_INCLUDE_DIR ${asio_SOURCE_DIR}/asio/include CACHE STRING "")
	set(ELEMENTS_BUILD_EXAMPLES OFF CACHE BOOL "")
	FetchContent_Declare(elements
		GIT_REPOSITORY https://github.com/PragmaTwice/elements
		GIT_TAG 8e4dfff096892ba16e437baaa0cecec3044bc231
		GIT_SUBMODULES_RECURSE ON
	)

	FetchContent_MakeAvailable(elements)
endif()

set(WIN32_VERSION 0x0A00)

execute_process(COMMAND git describe --tags
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	RESULT_VARIABLE GIT_DESCRIBE_EXITCODE
	OUTPUT_VARIABLE ENCAPSULE_VERSION
	ERROR_QUIET)

if(NOT GIT_DESCRIBE_EXITCODE EQUAL 0)
	set(ENCAPSULE_VERSION "v0.0.0-unknown")
	message(WARNING "failed to dump version via `git describe`, falling back to ${ENCAPSULE_VERSION}")
endif()

string(STRIP ${ENCAPSULE_VERSION} ENCAPSULE_VERSION)
configure_file(src/common/version.hpp.in src/common/version.hpp)

add_library(encapsule_common INTERFACE)
target_include_directories(encapsule_common INTERFACE src/common ${CMAKE_BINARY_DIR}/src/common)
target_compile_definitions(encapsule_common INTERFACE -D_WIN32_WINNT=${WIN32_VERSION} -DUNICODE)

set(INJECTEE_SRCS
	src/injectee/injectee.cpp
)

add_library(encapsule-injectee SHARED ${INJECTEE_SRCS})
target_compile_features(encapsule-injectee PUBLIC cxx_std_20)
target_link_libraries(encapsule-injectee PUBLIC minhook ws2_32 protopuf encapsule_common)
target_include_directories(encapsule-injectee PUBLIC ${asio_SOURCE_DIR}/asio/include)

if(NOT ENCAPSULE_INJECTEE_ONLY)
	set(INJECTOR_GUI_SRCS
		src/injector/injector_gui.cpp
		src/injector/ui_elements/dynamic_list.cpp
		src/injector/ui_elements/text_box.cpp
		src/injector/ui_elements/tooltip.cpp
	)

	set(ELEMENTS_APP_PROJECT encapsule)
	set(ELEMENTS_APP_SOURCES ${INJECTOR_GUI_SRCS})

	set(ELEMENTS_APP_ICON "resources/encapsule.rc")
	list(APPEND ELEMENTS_APP_SOURCES ${ELEMENTS_APP_ICON})

	set(ELEMENTS_ROOT ${elements_SOURCE_DIR})
	set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${ELEMENTS_ROOT}/cmake")
	include(ElementsConfigApp)

	target_compile_features(encapsule PUBLIC cxx_std_20)
	target_link_libraries(encapsule PUBLIC protopuf encapsule_common)
	target_include_directories(encapsule PUBLIC ${asio_SOURCE_DIR}/asio/include)

	set(INJECTOR_CLI_SRCS
		src/injector/injector_cli.cpp
	)

	add_executable(encapsule-cli ${INJECTOR_CLI_SRCS})
	target_compile_features(encapsule-cli PUBLIC cxx_std_20)
	target_link_libraries(encapsule-cli PUBLIC protopuf argparse spdlog encapsule_common advapi32)
	target_include_directories(encapsule-cli PUBLIC ${asio_SOURCE_DIR}/asio/include)
endif()

if(ENCAPSULE_INJECTEE_ONLY)
	add_executable(wow64-address-dumper src/wow64/address_dumper.cpp)
endif()

option(ENCAPSULE_BUILD_TESTS "build host-side CTest targets" ON)
enable_testing()
if(ENCAPSULE_BUILD_TESTS AND NOT ENCAPSULE_INJECTEE_ONLY)
	add_subdirectory(tests)
endif()
