include_directories(../)
add_library(ListProcesses SHARED ../ModuleCmd/ModuleCmd.cpp ListProcesses.cpp)
add_custom_command(TARGET ListProcesses POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:ListProcesses> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:ListProcesses>")

add_executable(testsListProcesses tests/testsListProcesses.cpp ../ModuleCmd/ModuleCmd.cpp ListProcesses.cpp)
target_link_libraries(testsListProcesses)
add_custom_command(TARGET testsListProcesses POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsListProcesses> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsListProcesses>")