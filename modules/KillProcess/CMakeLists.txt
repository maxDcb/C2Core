include_directories(../)
add_library(KillProcess SHARED KillProcess.cpp)
set_property(TARGET KillProcess PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(KillProcess )
add_custom_command(TARGET KillProcess POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:KillProcess> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:KillProcess>"
)

if(C2CORE_BUILD_TESTS)
    add_executable(testsKillProcess tests/testsKillProcess.cpp KillProcess.cpp)
    target_link_libraries(testsKillProcess )
    add_custom_command(TARGET testsKillProcess POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsKillProcess> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsKillProcess>")

    add_test(NAME testsKillProcess COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsKillProcess>")
endif()
