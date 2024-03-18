add_executable(testsModuleCmd tests/testsModuleCmd.cpp ModuleCmd.cpp ../../../thirdParty/base64/base64.cpp)
target_link_libraries(testsModuleCmd)
add_custom_command(TARGET testsModuleCmd POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsModuleCmd> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsModuleCmd>")

add_test(NAME testsModuleCmd COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsModuleCmd>")