include_directories(../)
add_library(Run SHARED Run.cpp)
set_property(TARGET Run PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Run )
add_custom_command(TARGET Run POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Run> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Run>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsRun tests/testsRun.cpp Run.cpp)
    target_compile_definitions(testsRun PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsRun )
    add_custom_command(TARGET testsRun POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsRun> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsRun>")

    add_test(NAME testsRun COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsRun>")
endif()
