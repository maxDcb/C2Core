include_directories(../)
add_library(Coff SHARED ../ModuleCmd/ModuleCmd.cpp CoffLoader.cpp)
target_link_libraries(Coff CoffLoader CoffPacker)
add_custom_command(TARGET Coff POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Coff> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Coff>")

add_executable(testsCoffLoader tests/testsCoffLoader.cpp ../ModuleCmd/ModuleCmd.cpp CoffLoader.cpp)
target_link_libraries(testsCoffLoader CoffLoader CoffPacker)
add_custom_command(TARGET testsCoffLoader POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsCoffLoader> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsCoffLoader>")