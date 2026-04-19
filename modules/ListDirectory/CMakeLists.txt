include_directories(../)
add_library(ListDirectory SHARED ListDirectory.cpp)
target_link_libraries(ListDirectory )
set_property(TARGET ListDirectory PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
add_custom_command(TARGET ListDirectory POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:ListDirectory> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:ListDirectory>")

if(C2CORE_BUILD_TESTS)
add_executable(testsListDirectory tests/testsListDirectory.cpp ListDirectory.cpp)
target_link_libraries(testsListDirectory )
add_custom_command(TARGET testsListDirectory POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsListDirectory> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsListDirectory>")

add_test(NAME testsListDirectory COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsListDirectory>")
endif()