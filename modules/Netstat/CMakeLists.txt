include_directories(../)
add_library(Netstat SHARED Netstat.cpp)
set_property(TARGET Netstat PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Netstat )
add_custom_command(TARGET Netstat POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:Netstat> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Netstat>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsNetstat tests/testsNetstat.cpp Netstat.cpp)
    target_compile_definitions(testsNetstat PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsNetstat )
    add_custom_command(TARGET testsNetstat POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsNetstat> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsNetstat>")
    add_test(NAME testsNetstat COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsNetstat>")
endif()
