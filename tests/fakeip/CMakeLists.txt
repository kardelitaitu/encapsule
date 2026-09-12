add_executable(encapsule_test_fakeip fakeip_test.cpp)
# fakeip.hpp is pure: no winsock, no protopuf, no asio -- nothing to link.
target_include_directories(encapsule_test_fakeip PRIVATE ${CMAKE_SOURCE_DIR}/tests ${CMAKE_SOURCE_DIR}/src/injectee)
add_test(NAME injectee.fakeip COMMAND encapsule_test_fakeip)
set_tests_properties(injectee.fakeip PROPERTIES TIMEOUT 60)
