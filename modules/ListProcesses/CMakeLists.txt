include_directories(../)
add_library(ListProcesses SHARED ListProcesses.cpp)
set_property(TARGET ListProcesses PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(ListProcesses )
add_custom_command(TARGET ListProcesses POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:ListProcesses> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:ListProcesses>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsListProcesses tests/testsListProcesses.cpp ListProcesses.cpp)
    target_compile_definitions(testsListProcesses PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsListProcesses )
    add_custom_command(TARGET testsListProcesses POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsListProcesses> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsListProcesses>")

    add_test(NAME testsListProcesses COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsListProcesses>")
endif()
