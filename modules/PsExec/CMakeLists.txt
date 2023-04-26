include_directories(../)
add_library(PsExec SHARED ../ModuleCmd/ModuleCmd.cpp PsExec.cpp)
add_custom_command(TARGET PsExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:PsExec> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:PsExec>")

add_executable(testsPsExec tests/testsPsExec.cpp ../ModuleCmd/ModuleCmd.cpp PsExec.cpp)
target_link_libraries(testsPsExec)
add_custom_command(TARGET testsPsExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsPsExec> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsPsExec>")