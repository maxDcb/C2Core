include_directories(../)
add_library(Script SHARED ../ModuleCmd/ModuleCmd.cpp Script.cpp)
add_custom_command(TARGET Script POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Script> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Script>")

add_executable(testsScript tests/testsScript.cpp ../ModuleCmd/ModuleCmd.cpp Script.cpp)
target_link_libraries(testsScript)
add_custom_command(TARGET testsScript POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsScript> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsScript>")

add_test(NAME testsScript COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsScript>")