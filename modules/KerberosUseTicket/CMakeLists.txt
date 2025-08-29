include_directories(../)
add_library(KerberosUseTicket SHARED KerberosUseTicket.cpp)
set_property(TARGET KerberosUseTicket PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(KerberosUseTicket )
add_custom_command(TARGET KerberosUseTicket POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:KerberosUseTicket> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:KerberosUseTicket>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsKerberosUseTicket tests/testsKerberosUseTicket.cpp KerberosUseTicket.cpp)
    target_link_libraries(testsKerberosUseTicket )
    add_custom_command(TARGET testsKerberosUseTicket POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsKerberosUseTicket> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsKerberosUseTicket>")

    add_test(NAME testsKerberosUseTicket COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsKerberosUseTicket>")
endif()