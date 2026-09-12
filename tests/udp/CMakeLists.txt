add_executable(encapsule_test_udp udp_test.cpp)
# udp_state.hpp is pure: no winsock, no protopuf, no asio -- nothing to link.
target_include_directories(encapsule_test_udp PRIVATE ${CMAKE_SOURCE_DIR}/tests ${CMAKE_SOURCE_DIR}/src/injectee)
add_test(NAME injectee.udp COMMAND encapsule_test_udp)
set_tests_properties(injectee.udp PROPERTIES TIMEOUT 60)
