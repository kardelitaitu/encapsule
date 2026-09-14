add_executable(encapsule_test_fake_map fake_map_test.cpp)
# fake_map.hpp is pure as well: <winsock2.h> for the address LAYOUTS only, and
# not one winsock CALL, so there is no ws2_32 to link and no socket to open.
target_include_directories(encapsule_test_fake_map PRIVATE ${CMAKE_SOURCE_DIR}/tests ${CMAKE_SOURCE_DIR}/src/injectee)
# The same _WIN32_WINNT floor the injectee is built with (CMakeLists.txt:81,
# 99) -- the sockaddr layouts are declared only from it up.  Asked for here
# rather than got by linking encapsule_common, which would also drag the
# protopuf include path in for a test that has nothing to link.
target_compile_definitions(encapsule_test_fake_map PRIVATE _WIN32_WINNT=${WIN32_VERSION})
add_test(NAME injectee.fake_map COMMAND encapsule_test_fake_map)
set_tests_properties(injectee.fake_map PROPERTIES TIMEOUT 60)
