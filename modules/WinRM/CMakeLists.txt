include_directories(../)
add_library(WinRM SHARED WinRM.cpp)
set_property(TARGET WinRM PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
add_custom_command(TARGET WinRM POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
$<TARGET_FILE:WinRM> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:WinRM>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsWinRM tests/testsWinRM.cpp WinRM.cpp)
    add_custom_command(TARGET testsWinRM POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsWinRM> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsWinRM>")

    add_test(NAME testsWinRM COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsWinRM>")
endif()
