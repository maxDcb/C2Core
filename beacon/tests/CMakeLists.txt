include_directories(..)
include_directories(../../modules/ModuleCmd)

add_executable(testBeacon testBeacon.cpp)
target_link_libraries(testBeacon SocketHandler PipeHandler)
add_custom_command(TARGET testBeacon POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testBeacon> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeacon>")
add_test(NAME testBeacon COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeacon>")

add_executable(testBeaconDns testBeaconDns.cpp)
target_link_libraries(testBeaconDns SocketHandler Dnscommunication PipeHandler)
add_custom_command(TARGET testBeaconDns POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testBeaconDns> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconDns>")
add_test(NAME testBeaconDns COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconDns>")

add_executable(testBeaconGithub testBeaconGithub.cpp)
target_link_libraries(testBeaconGithub SocketHandler PipeHandler)
add_custom_command(TARGET testBeaconGithub POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testBeaconGithub> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconGithub>")
add_test(NAME testBeaconGithub COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconGithub>")

add_executable(testBeaconHttp testBeaconHttp.cpp)
target_link_libraries(testBeaconHttp SocketHandler PipeHandler)
add_custom_command(TARGET testBeaconHttp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testBeaconHttp> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconHttp>")
add_test(NAME testBeaconHttp COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconHttp>")

add_executable(testBeaconSmb testBeaconSmb.cpp)
target_link_libraries(testBeaconSmb SocketHandler PipeHandler)
add_custom_command(TARGET testBeaconSmb POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testBeaconSmb> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconSmb>")
add_test(NAME testBeaconSmb COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconSmb>")

add_executable(testBeaconTcp testBeaconTcp.cpp)
target_link_libraries(testBeaconTcp SocketHandler PipeHandler)
add_custom_command(TARGET testBeaconTcp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testBeaconTcp> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconTcp>")
add_test(NAME testBeaconTcp COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconTcp>")
