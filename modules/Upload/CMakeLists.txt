include_directories(../)
add_library(Upload SHARED Upload.cpp)
target_link_libraries(Upload spdlog::spdlog nlohmann_json::nlohmann_json)
add_custom_command(TARGET Upload POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Upload> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Upload>")

if(WITH_TESTS)
    add_executable(testsUpload tests/testsUpload.cpp Upload.cpp)
    target_link_libraries(testsUpload spdlog::spdlog nlohmann_json::nlohmann_json)
    add_custom_command(TARGET testsUpload POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsUpload> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsUpload>")

    add_test(NAME testsUpload COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsUpload>")
endif()