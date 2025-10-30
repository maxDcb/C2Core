include_directories(../)
add_library(EnumerateRdpSessions SHARED EnumerateRdpSessions.cpp)
set_property(TARGET EnumerateRdpSessions PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
if (WIN32)
    target_compile_definitions(EnumerateRdpSessions PRIVATE _WIN32_WINNT=0x0601)
    target_link_libraries(EnumerateRdpSessions PRIVATE Wtsapi32)
endif()
add_custom_command(TARGET EnumerateRdpSessions POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:EnumerateRdpSessions> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:EnumerateRdpSessions>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsEnumerateRdpSessions tests/testsEnumerateRdpSessions.cpp EnumerateRdpSessions.cpp)
    if (WIN32)
        target_compile_definitions(testsEnumerateRdpSessions PRIVATE _WIN32_WINNT=0x0601)
        target_link_libraries(testsEnumerateRdpSessions PRIVATE Wtsapi32)
    endif()
    add_custom_command(TARGET testsEnumerateRdpSessions POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsEnumerateRdpSessions> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsEnumerateRdpSessions>")

    add_test(NAME testsEnumerateRdpSessions COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsEnumerateRdpSessions>")
endif()
