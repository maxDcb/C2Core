include_directories(../)
add_library(Chisel SHARED ../ModuleCmd/ModuleCmd.cpp Chisel.cpp)
target_link_libraries(Chisel ${Donut})
add_custom_command(TARGET Chisel POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Chisel> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Chisel>")

add_executable(testsChisel tests/testsChisel.cpp ../ModuleCmd/ModuleCmd.cpp Chisel.cpp)
target_link_libraries(testsChisel ${Donut})
add_custom_command(TARGET testsChisel POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsChisel> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsChisel>")