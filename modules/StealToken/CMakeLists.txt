include_directories(../)
add_library(StealToken SHARED ../ModuleCmd/ModuleCmd.cpp StealToken.cpp)
add_custom_command(TARGET StealToken POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:StealToken> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:StealToken>")

add_executable(testsStealToken tests/testsStealToken.cpp ../ModuleCmd/ModuleCmd.cpp StealToken.cpp)
target_link_libraries(testsStealToken)
add_custom_command(TARGET testsStealToken POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsStealToken> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsStealToken>")

add_test(NAME testsStealToken COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsStealToken>")