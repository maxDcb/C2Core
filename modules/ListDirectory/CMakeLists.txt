include_directories(../)
add_library(ListDirectory SHARED ListDirectory.cpp)
target_link_libraries(ListDirectory spdlog::spdlog nlohmann_json::nlohmann_json)
add_custom_command(TARGET ListDirectory POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:ListDirectory> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:ListDirectory>")

if(WITH_TESTS)
add_executable(testsListDirectory tests/testsListDirectory.cpp ListDirectory.cpp)
target_link_libraries(testsListDirectory spdlog::spdlog nlohmann_json::nlohmann_json)
add_custom_command(TARGET testsListDirectory POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsListDirectory> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsListDirectory>")

add_test(NAME testsListDirectory COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsListDirectory>")
endif()