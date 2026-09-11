set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test_bin")

add_subdirectory(schema)
add_subdirectory(utils)
add_subdirectory(winnet)
add_subdirectory(queue)
add_subdirectory(e2e)
