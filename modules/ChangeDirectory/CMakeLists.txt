include_directories(../)
add_library(ChangeDirectory SHARED ChangeDirectory.cpp)
add_custom_command(TARGET ChangeDirectory POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:ChangeDirectory> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:ChangeDirectory>")

add_executable(testsChangeDirectory tests/testsChangeDirectory.cpp ChangeDirectory.cpp)
add_custom_command(TARGET testsChangeDirectory POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsChangeDirectory> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsChangeDirectory>")

add_test(NAME testsChangeDirectory COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsChangeDirectory>")