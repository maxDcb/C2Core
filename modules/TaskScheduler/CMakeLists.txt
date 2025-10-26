include_directories(../)
add_library(TaskScheduler SHARED TaskScheduler.cpp)
set_property(TARGET TaskScheduler PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
if (WIN32)
    target_compile_definitions(TaskScheduler PRIVATE _WIN32_WINNT=0x0601)
    target_link_libraries(TaskScheduler PRIVATE Taskschd)
endif()
add_custom_command(TARGET TaskScheduler POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
$<TARGET_FILE:TaskScheduler> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:TaskScheduler>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsTaskScheduler tests/testsTaskScheduler.cpp TaskScheduler.cpp)
    if (WIN32)
        target_compile_definitions(testsTaskScheduler PRIVATE _WIN32_WINNT=0x0601)
        target_link_libraries(testsTaskScheduler PRIVATE Taskschd)
    endif()
    add_custom_command(TARGET testsTaskScheduler POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsTaskScheduler> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsTaskScheduler>")

    add_test(NAME testsTaskScheduler COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsTaskScheduler>")
endif()
