include_directories(../)
add_library(TaskScheduler SHARED TaskScheduler.cpp)
set_property(TARGET TaskScheduler PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
if (WIN32)
    target_compile_definitions(TaskScheduler PRIVATE _WIN32_WINNT=0x0601)
    target_link_libraries(TaskScheduler PRIVATE Taskschd)
endif()
add_custom_command(TARGET TaskScheduler POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
$<TARGET_FILE:TaskScheduler> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:TaskScheduler>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsTaskScheduler tests/testsTaskScheduler.cpp TaskScheduler.cpp)
    target_link_libraries(testsTaskScheduler PRIVATE c2_base64)
    if (WIN32)
        target_compile_definitions(testsTaskScheduler PRIVATE _WIN32_WINNT=0x0601)
        target_link_libraries(testsTaskScheduler PRIVATE Taskschd)
    endif()
    add_custom_command(TARGET testsTaskScheduler POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsTaskScheduler> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTaskScheduler>")

    add_test(NAME testsTaskScheduler COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTaskScheduler>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_executable(testsTaskSchedulerFunctional tests/functional/testsTaskSchedulerFunctional.cpp TaskScheduler.cpp)
    target_link_libraries(testsTaskSchedulerFunctional PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(testsTaskSchedulerFunctional PRIVATE C2CORE_BUILD_FUNCTIONAL_TESTS)
    target_include_directories(testsTaskSchedulerFunctional PRIVATE ../tests)
    if (WIN32)
        target_compile_definitions(testsTaskSchedulerFunctional PRIVATE _WIN32_WINNT=0x0601)
        target_link_libraries(testsTaskSchedulerFunctional PRIVATE Taskschd)
    endif()
    add_custom_command(TARGET testsTaskSchedulerFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsTaskSchedulerFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTaskSchedulerFunctional>")

    add_test(NAME testsTaskSchedulerFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTaskSchedulerFunctional>")
    set_tests_properties(testsTaskSchedulerFunctional PROPERTIES LABELS "functional;taskscheduler;windows-network" SKIP_RETURN_CODE 77)
endif()
