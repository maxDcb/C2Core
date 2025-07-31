include_directories(../)
add_library(IpConfig SHARED IpConfig.cpp)
set_property(TARGET IpConfig PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(IpConfig )
add_custom_command(TARGET IpConfig POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:IpConfig> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:IpConfig>")

if(WITH_TESTS)
    add_executable(testsIpConfig tests/testsIpConfig.cpp IpConfig.cpp)
    target_link_libraries(testsIpConfig )
    add_custom_command(TARGET testsIpConfig POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsIpConfig> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsIpConfig>")
    add_test(NAME testsIpConfig COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsIpConfig>")
endif()
