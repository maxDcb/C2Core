include_directories(../)
add_library(PrintWorkingDirectory SHARED PrintWorkingDirectory.cpp)
target_link_libraries(PrintWorkingDirectory spdlog::spdlog nlohmann_json::nlohmann_json)
add_custom_command(TARGET PrintWorkingDirectory POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:PrintWorkingDirectory> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:PrintWorkingDirectory>")

if(WITH_TESTS)
    add_executable(testsPrintWorkingDirectory tests/testsPrintWorkingDirectory.cpp PrintWorkingDirectory.cpp)
    target_link_libraries(testsPrintWorkingDirectory spdlog::spdlog nlohmann_json::nlohmann_json)
    add_custom_command(TARGET testsPrintWorkingDirectory POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsPrintWorkingDirectory> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsPrintWorkingDirectory>")

    add_test(NAME testsPrintWorkingDirectory COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsPrintWorkingDirectory>")
endif()