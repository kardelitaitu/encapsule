add_executable(encapsule_test_queue queue_test.cpp)
target_link_libraries(encapsule_test_queue PRIVATE encapsule_common protopuf ws2_32)
target_include_directories(encapsule_test_queue PRIVATE ${CMAKE_SOURCE_DIR}/tests ${asio_SOURCE_DIR}/asio/include)
add_test(NAME common.queue COMMAND encapsule_test_queue)
# Worst case is "as many scenarios hang as the file has", not "the suite is
# slow" (green, this binary finishes in well under a second).  Every scenario
# is capped by kWatchdogMs in queue_test.cpp, and that file's main() asserts it
# still holds exactly kScenarioCount of them -- so adding a RUN() line without
# moving BOTH numbers fails the binary.  Do not just double this in silence.
#   kScenarioCount(12) x kWatchdogMs(8000ms) = 96s of hangs, worst case
#   + 24s margin (process start, per-thread io_context teardown, and the
#     deliberate leak-and-continue path after a scenario is reported hung)
#   = 120
set_tests_properties(common.queue PROPERTIES TIMEOUT 120)
