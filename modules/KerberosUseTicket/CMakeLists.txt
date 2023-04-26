include_directories(../)
add_library(KerberosUseTicket SHARED ../ModuleCmd/ModuleCmd.cpp KerberosUseTicket.cpp)
add_custom_command(TARGET KerberosUseTicket POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:KerberosUseTicket> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:KerberosUseTicket>")

add_executable(testsKerberosUseTicket tests/testsKerberosUseTicket.cpp ../ModuleCmd/ModuleCmd.cpp KerberosUseTicket.cpp)
target_link_libraries(testsKerberosUseTicket)
add_custom_command(TARGET testsKerberosUseTicket POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsKerberosUseTicket> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsKerberosUseTicket>")