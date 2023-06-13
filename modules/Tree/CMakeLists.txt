include_directories(../)
add_library(Tree SHARED ../ModuleCmd/ModuleCmd.cpp Tree.cpp)
add_custom_command(TARGET Tree POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Tree> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Tree>")

add_executable(testsTree tests/testsTree.cpp ../ModuleCmd/ModuleCmd.cpp Tree.cpp)
target_link_libraries(testsTree)
add_custom_command(TARGET testsTree POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsTree> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsTree>")