include_directories(../)
add_library(Registry SHARED Registry.cpp)
set_property(TARGET Registry PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
if (WIN32)
    target_compile_definitions(Registry PRIVATE _WIN32_WINNT=0x0601)
    target_link_libraries(Registry PRIVATE Advapi32)
endif()
add_custom_command(TARGET Registry POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:Registry> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Registry>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsRegistry tests/testsRegistry.cpp Registry.cpp)
    if (WIN32)
        target_compile_definitions(testsRegistry PRIVATE _WIN32_WINNT=0x0601)
        target_link_libraries(testsRegistry PRIVATE Advapi32)
    endif()
    add_custom_command(TARGET testsRegistry POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsRegistry> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsRegistry>")

    add_test(NAME testsRegistry COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsRegistry>")
endif()
