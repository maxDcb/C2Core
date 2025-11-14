include_directories(../)
add_library(ReversePortForward SHARED ReversePortForward.cpp)
set_property(TARGET ReversePortForward PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(ReversePortForward)
add_custom_command(TARGET ReversePortForward POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:ReversePortForward> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:ReversePortForward>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsReversePortForward tests/testsReversePortForward.cpp ReversePortForward.cpp)
    target_link_libraries(testsReversePortForward)
    add_custom_command(TARGET testsReversePortForward POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsReversePortForward> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsReversePortForward>")
    add_test(NAME testsReversePortForward COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsReversePortForward>")
endif()
