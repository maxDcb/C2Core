add_library(HostContext SHARED HostContext.cpp)
set_property(TARGET HostContext PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
add_custom_command(TARGET HostContext POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:HostContext> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:HostContext>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsHostContext tests/testsHostContext.cpp HostContext.cpp)
    add_custom_command(TARGET testsHostContext POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsHostContext> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsHostContext>")
    add_test(NAME testsHostContext COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsHostContext>")
endif()
