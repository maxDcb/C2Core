include_directories(../)
add_library(WmiExec SHARED WmiExec.cpp)
target_link_libraries(WmiExec spdlog::spdlog nlohmann_json::nlohmann_json)
add_custom_command(TARGET WmiExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:WmiExec> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:WmiExec>")

if(WITH_TESTS)
    add_executable(testsWmiExec tests/testsWmiExec.cpp WmiExec.cpp)
    target_link_libraries(testsWmiExec spdlog::spdlog nlohmann_json::nlohmann_json)
    add_custom_command(TARGET testsWmiExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsWmiExec> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsWmiExec>")

    add_test(NAME testsWmiExec COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsWmiExec>")
endif()