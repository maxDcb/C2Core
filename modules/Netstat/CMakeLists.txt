include_directories(../)
add_library(Netstat SHARED Netstat.cpp)
set_property(TARGET Netstat PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Netstat )
add_custom_command(TARGET Netstat POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:Netstat> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Netstat>")

if(WITH_TESTS)
    add_executable(testsNetstat tests/testsNetstat.cpp Netstat.cpp)
    target_link_libraries(testsNetstat )
    add_custom_command(TARGET testsNetstat POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsNetstat> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsNetstat>")
    add_test(NAME testsNetstat COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsNetstat>")
endif()
