include_directories(../)
add_library(Shell SHARED Shell.cpp)
set_property(TARGET Shell PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Shell)
add_custom_command(TARGET Shell POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:Shell> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Shell>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsShell tests/testsShell.cpp Shell.cpp)
    target_compile_definitions(testsShell PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsShell)
    add_custom_command(TARGET testsShell POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsShell> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsShell>")
    add_test(NAME testsShell COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsShell>")
endif()
