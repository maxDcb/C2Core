include_directories(../)
add_library(PrintWorkingDirectory SHARED ../ModuleCmd/ModuleCmd.cpp PrintWorkingDirectory.cpp)
add_custom_command(TARGET PrintWorkingDirectory POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:PrintWorkingDirectory> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:PrintWorkingDirectory>")

add_executable(testsPrintWorkingDirectory tests/testsPrintWorkingDirectory.cpp ../ModuleCmd/ModuleCmd.cpp PrintWorkingDirectory.cpp)
target_link_libraries(testsPrintWorkingDirectory)
add_custom_command(TARGET testsPrintWorkingDirectory POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsPrintWorkingDirectory> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsPrintWorkingDirectory>")