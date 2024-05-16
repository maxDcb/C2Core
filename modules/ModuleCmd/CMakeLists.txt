
if(WITH_TESTS)
    add_executable(testsModuleCmd tests/testsModuleCmd.cpp ../../../thirdParty/base64/base64.cpp)
    target_link_libraries(testsModuleCmd spdlog::spdlog nlohmann_json::nlohmann_json)
    add_custom_command(TARGET testsModuleCmd POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsModuleCmd> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsModuleCmd>")
    add_test(NAME testsModuleCmd COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsModuleCmd>")

    add_executable(testsTools tests/testsTools.cpp ../../../thirdParty/base64/base64.cpp)
    target_link_libraries(testsTools spdlog::spdlog nlohmann_json::nlohmann_json)
    add_custom_command(TARGET testsTools POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsTools> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsTools>")

    add_test(NAME testsTools COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsTools>")
endif()