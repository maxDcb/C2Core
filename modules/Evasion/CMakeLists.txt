include_directories(../)
add_library(Evasion SHARED ../ModuleCmd/ModuleCmd.cpp Evasion.cpp)
target_link_libraries(Evasion)
add_custom_command(TARGET Evasion POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Evasion> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Evasion>")

add_executable(testsEvasion tests/testsEvasion.cpp ../ModuleCmd/ModuleCmd.cpp Evasion.cpp)
target_link_libraries(testsEvasion)
add_custom_command(TARGET testsEvasion POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsEvasion> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsEvasion>")

add_test(NAME testsEvasion COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsEvasion>")