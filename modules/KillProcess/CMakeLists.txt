include_directories(../)
add_library(KillProcess SHARED KillProcess.cpp)
set_property(TARGET KillProcess PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(KillProcess )
add_custom_command(TARGET KillProcess POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:KillProcess> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:KillProcess>"
)

if(WITH_TESTS)
    add_executable(testsKillProcess tests/testsKillProcess.cpp KillProcess.cpp)
    target_link_libraries(testsKillProcess )
    add_custom_command(TARGET testsKillProcess POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsKillProcess> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsKillProcess>")

    add_test(NAME testsKillProcess COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsKillProcess>")
endif()
