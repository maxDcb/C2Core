include_directories(..)
include_directories(../../modules/ModuleCmd)

# Test testBeacon
add_executable(testBeacon 
testBeacon.cpp 
../Beacon.cpp
../../listener/Listener.cpp
../../listener/ListenerTcp.cpp	
../../listener/ListenerSmb.cpp	
../../../thirdParty/base64/base64.cpp)
IF (WIN32)
    set_property(TARGET testBeacon PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_libraries(testBeacon SocketHandler PipeHandler MemoryModule SocksServer )
ELSE()
    target_link_libraries(testBeacon SocketHandler PipeHandler MemoryModule SocksServer )
ENDIF()
add_custom_command(TARGET testBeacon POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testBeacon> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeacon>")
add_test(NAME testBeacon COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeacon>")

# Test testBeaconDns
add_executable(testBeaconDns 
testBeaconDns.cpp 
../Beacon.cpp
../../listener/Listener.cpp
../../listener/ListenerTcp.cpp	
../../listener/ListenerSmb.cpp	
../../../thirdParty/base64/base64.cpp)
IF (WIN32)
    set_property(TARGET testBeaconDns PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_libraries(testBeaconDns SocketHandler Dnscommunication PipeHandler MemoryModule SocksServer )
ELSE()
    target_link_libraries(testBeaconDns SocketHandler Dnscommunication PipeHandler MemoryModule SocksServer )
ENDIF()
add_custom_command(TARGET testBeaconDns POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testBeaconDns> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconDns>")
add_test(NAME testBeaconDns COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconDns>")

# Test testBeaconGithub
add_executable(testBeaconGithub 
testBeaconGithub.cpp 
../Beacon.cpp
../../listener/Listener.cpp
../../listener/ListenerTcp.cpp	
../../listener/ListenerSmb.cpp	
../../../thirdParty/base64/base64.cpp)
IF (WIN32)
    set_property(TARGET testBeaconGithub PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_libraries(testBeaconGithub SocketHandler PipeHandler MemoryModule SocksServer )
ELSE()
    target_link_libraries(testBeaconGithub SocketHandler PipeHandler MemoryModule SocksServer  httplib::httplib)
ENDIF()
add_custom_command(TARGET testBeaconGithub POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testBeaconGithub> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconGithub>")
add_test(NAME testBeaconGithub COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconGithub>")

# Test testBeaconHttp
add_executable(testBeaconHttp 
testBeaconHttp.cpp 
../Beacon.cpp
../../listener/Listener.cpp
../../listener/ListenerTcp.cpp	
../../listener/ListenerSmb.cpp	
../../../thirdParty/base64/base64.cpp)
IF (WIN32)
    set_property(TARGET testBeaconHttp PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_libraries(testBeaconHttp SocketHandler PipeHandler MemoryModule SocksServer )
ELSE()
    target_link_libraries(testBeaconHttp SocketHandler PipeHandler MemoryModule SocksServer  httplib::httplib)
ENDIF()
add_custom_command(TARGET testBeaconHttp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testBeaconHttp> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconHttp>")
add_test(NAME testBeaconHttp COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconHttp>")

# Test testBeaconSmb
add_executable(testBeaconSmb 
testBeaconSmb.cpp 
../Beacon.cpp
../../listener/Listener.cpp
../../listener/ListenerTcp.cpp	
../../listener/ListenerSmb.cpp	
../../../thirdParty/base64/base64.cpp)
IF (WIN32)
    set_property(TARGET testBeaconSmb PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_libraries(testBeaconSmb SocketHandler PipeHandler MemoryModule SocksServer )
ELSE()
    target_link_libraries(testBeaconSmb SocketHandler PipeHandler MemoryModule SocksServer )
ENDIF()
add_custom_command(TARGET testBeaconSmb POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testBeaconSmb> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconSmb>")
add_test(NAME testBeaconSmb COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconSmb>")

# Test testBeaconTcp
add_executable(testBeaconTcp 
testBeaconTcp.cpp 
../Beacon.cpp
../../listener/Listener.cpp
../../listener/ListenerTcp.cpp	
../../listener/ListenerSmb.cpp	
../../../thirdParty/base64/base64.cpp)
IF (WIN32)
    set_property(TARGET testBeaconTcp PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_libraries(testBeaconTcp SocketHandler PipeHandler MemoryModule SocksServer )
ELSE()
    target_link_libraries(testBeaconTcp SocketHandler PipeHandler MemoryModule SocksServer )
ENDIF()
add_custom_command(TARGET testBeaconTcp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testBeaconTcp> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconTcp>")
add_test(NAME testBeaconTcp COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testBeaconTcp>")
