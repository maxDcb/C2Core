include_directories(../)
add_library(Script SHARED Script.cpp)
set_property(TARGET Script PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Script )
add_custom_command(TARGET Script POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Script> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Script>")

if(WITH_TESTS)
    add_executable(testsScript tests/testsScript.cpp Script.cpp)
    target_link_libraries(testsScript )
    add_custom_command(TARGET testsScript POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsScript> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsScript>")

    add_test(NAME testsScript COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsScript>")
endif()