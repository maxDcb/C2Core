include_directories(../)
add_library(WinRM SHARED WinRM.cpp)
set_property(TARGET WinRM PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
add_custom_command(TARGET WinRM POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
$<TARGET_FILE:WinRM> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:WinRM>")

if(WIN32)
    target_link_libraries(WinRM PRIVATE WsmSvc)
endif()

if(C2CORE_BUILD_TESTS)
    add_executable(testsWinRM tests/testsWinRM.cpp WinRM.cpp)
    target_link_libraries(testsWinRM PRIVATE c2_base64)
    if(WIN32)
        target_link_libraries(testsWinRM PRIVATE WsmSvc)
    endif()
    add_custom_command(TARGET testsWinRM POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsWinRM> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsWinRM>")

    add_test(NAME testsWinRM COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsWinRM>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_executable(testsWinRMFunctional tests/functional/testsWinRMFunctional.cpp WinRM.cpp)
    target_link_libraries(testsWinRMFunctional PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    target_include_directories(testsWinRMFunctional PRIVATE ../tests)
    target_compile_definitions(testsWinRMFunctional PRIVATE C2CORE_BUILD_FUNCTIONAL_TESTS)
    if(WIN32)
        target_link_libraries(testsWinRMFunctional PRIVATE WsmSvc)
    endif()
    add_custom_command(TARGET testsWinRMFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsWinRMFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsWinRMFunctional>")

    add_test(NAME testsWinRMFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsWinRMFunctional>")
    set_tests_properties(testsWinRMFunctional PROPERTIES LABELS "functional;winrm;windows-network" SKIP_RETURN_CODE 77)
endif()
