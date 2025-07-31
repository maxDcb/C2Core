include_directories(../)
add_library(Shell SHARED Shell.cpp)
set_property(TARGET Shell PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Shell)
add_custom_command(TARGET Shell POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:Shell> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Shell>")

if(WITH_TESTS)
    add_executable(testsShell tests/testsShell.cpp Shell.cpp)
    target_link_libraries(testsShell)
    add_custom_command(TARGET testsShell POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsShell> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsShell>")
    add_test(NAME testsShell COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsShell>")
endif()
