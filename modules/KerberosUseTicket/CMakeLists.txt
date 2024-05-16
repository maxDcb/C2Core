include_directories(../)
add_library(KerberosUseTicket SHARED KerberosUseTicket.cpp)
target_link_libraries(KerberosUseTicket spdlog::spdlog nlohmann_json::nlohmann_json)
add_custom_command(TARGET KerberosUseTicket POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:KerberosUseTicket> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:KerberosUseTicket>")

if(WITH_TESTS)
    add_executable(testsKerberosUseTicket tests/testsKerberosUseTicket.cpp KerberosUseTicket.cpp)
    target_link_libraries(testsKerberosUseTicket spdlog::spdlog nlohmann_json::nlohmann_json)
    add_custom_command(TARGET testsKerberosUseTicket POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsKerberosUseTicket> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsKerberosUseTicket>")

    add_test(NAME testsKerberosUseTicket COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsKerberosUseTicket>")
endif()