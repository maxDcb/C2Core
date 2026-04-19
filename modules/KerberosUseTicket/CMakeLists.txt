include_directories(../)
add_library(KerberosUseTicket SHARED KerberosUseTicket.cpp)
set_property(TARGET KerberosUseTicket PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(KerberosUseTicket )
add_custom_command(TARGET KerberosUseTicket POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:KerberosUseTicket> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:KerberosUseTicket>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsKerberosUseTicket tests/testsKerberosUseTicket.cpp KerberosUseTicket.cpp)
    target_link_libraries(testsKerberosUseTicket )
    add_custom_command(TARGET testsKerberosUseTicket POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsKerberosUseTicket> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsKerberosUseTicket>")

    add_test(NAME testsKerberosUseTicket COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsKerberosUseTicket>")
endif()