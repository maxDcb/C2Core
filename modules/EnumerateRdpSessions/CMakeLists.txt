include_directories(../)
add_library(EnumerateRdpSessions SHARED EnumerateRdpSessions.cpp)
set_property(TARGET EnumerateRdpSessions PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
if (WIN32)
    target_compile_definitions(EnumerateRdpSessions PRIVATE _WIN32_WINNT=0x0601)
    target_link_libraries(EnumerateRdpSessions PRIVATE Wtsapi32)
endif()
add_custom_command(TARGET EnumerateRdpSessions POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:EnumerateRdpSessions> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:EnumerateRdpSessions>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsEnumerateRdpSessions tests/testsEnumerateRdpSessions.cpp EnumerateRdpSessions.cpp)
    if (WIN32)
        target_compile_definitions(testsEnumerateRdpSessions PRIVATE _WIN32_WINNT=0x0601)
        target_link_libraries(testsEnumerateRdpSessions PRIVATE Wtsapi32)
    endif()
    add_custom_command(TARGET testsEnumerateRdpSessions POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsEnumerateRdpSessions> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsEnumerateRdpSessions>")

    add_test(NAME testsEnumerateRdpSessions COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsEnumerateRdpSessions>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_executable(testsEnumerateRdpSessionsFunctional tests/functional/testsEnumerateRdpSessionsFunctional.cpp EnumerateRdpSessions.cpp)
    target_include_directories(testsEnumerateRdpSessionsFunctional PRIVATE ../tests)
    target_compile_definitions(testsEnumerateRdpSessionsFunctional PRIVATE C2CORE_BUILD_FUNCTIONAL_TESTS)
    target_link_libraries(testsEnumerateRdpSessionsFunctional PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    if (WIN32)
        target_compile_definitions(testsEnumerateRdpSessionsFunctional PRIVATE _WIN32_WINNT=0x0601)
        target_link_libraries(testsEnumerateRdpSessionsFunctional PRIVATE Wtsapi32)
    endif()
    add_custom_command(TARGET testsEnumerateRdpSessionsFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsEnumerateRdpSessionsFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsEnumerateRdpSessionsFunctional>")

    add_test(NAME testsEnumerateRdpSessionsFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsEnumerateRdpSessionsFunctional>")
    set_tests_properties(testsEnumerateRdpSessionsFunctional PROPERTIES LABELS "functional;rdp;windows-network" SKIP_RETURN_CODE 77)
endif()
