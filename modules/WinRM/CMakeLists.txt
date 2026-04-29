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
    if(WIN32)
        target_link_libraries(testsWinRM PRIVATE WsmSvc)
    endif()
    add_custom_command(TARGET testsWinRM POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsWinRM> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsWinRM>")

    add_test(NAME testsWinRM COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsWinRM>")
endif()
