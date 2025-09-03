include_directories(../modules/ModuleCmd)


set(SOURCES_BEACON_HTTP_EXE
	Beacon.cpp
	BeaconHttp.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)

add_library(BeaconHttpLib ${SOURCES_BEACON_HTTP_EXE})
target_include_directories(BeaconHttpLib PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}> $<INSTALL_INTERFACE:include>)
if(WIN32)
        set_property(TARGET BeaconHttpLib PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
        target_link_libraries(BeaconHttpLib PUBLIC
                $<BUILD_INTERFACE:SocketHandler>
                $<BUILD_INTERFACE:PipeHandler>
                $<BUILD_INTERFACE:MemoryModule>
                $<BUILD_INTERFACE:SocksServer>
                $<INSTALL_INTERFACE:SocketHandler>
                $<INSTALL_INTERFACE:PipeHandler>
                $<INSTALL_INTERFACE:MemoryModule>
                $<INSTALL_INTERFACE:SocksServer>)
else()
        target_link_libraries(BeaconHttpLib PUBLIC
                $<BUILD_INTERFACE:SocketHandler>
                $<BUILD_INTERFACE:PipeHandler>
                $<BUILD_INTERFACE:MemoryModule>
                $<BUILD_INTERFACE:SocksServer>
                $<BUILD_INTERFACE:openssl::openssl>
                $<BUILD_INTERFACE:httplib::httplib>
                $<BUILD_INTERFACE:dl>
                $<INSTALL_INTERFACE:SocketHandler>
                $<INSTALL_INTERFACE:PipeHandler>
                $<INSTALL_INTERFACE:MemoryModule>
                $<INSTALL_INTERFACE:SocksServer>
                $<INSTALL_INTERFACE:openssl::openssl>
                $<INSTALL_INTERFACE:httplib::httplib>
                $<INSTALL_INTERFACE:dl>)
endif()
# add_custom_command(TARGET BeaconHttpLib POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
# $<TARGET_FILE:BeaconHttpLib> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconHttpLib>")


set(SOURCES_BEACON_TCP_EXE
	Beacon.cpp
	BeaconTcp.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)

add_library(BeaconTcpLib ${SOURCES_BEACON_TCP_EXE})
target_include_directories(BeaconTcpLib PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}> $<INSTALL_INTERFACE:include>)
if(WIN32)
        set_property(TARGET BeaconTcpLib PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
        target_link_libraries(BeaconTcpLib PUBLIC
                $<BUILD_INTERFACE:SocketHandler>
                $<BUILD_INTERFACE:PipeHandler>
                $<BUILD_INTERFACE:MemoryModule>
                $<BUILD_INTERFACE:SocksServer>
                $<INSTALL_INTERFACE:SocketHandler>
                $<INSTALL_INTERFACE:PipeHandler>
                $<INSTALL_INTERFACE:MemoryModule>
                $<INSTALL_INTERFACE:SocksServer>)
else()
        target_link_libraries(BeaconTcpLib PUBLIC
                $<BUILD_INTERFACE:SocketHandler>
                $<BUILD_INTERFACE:PipeHandler>
                $<BUILD_INTERFACE:MemoryModule>
                $<BUILD_INTERFACE:SocksServer>
                $<BUILD_INTERFACE:dl>
                $<INSTALL_INTERFACE:SocketHandler>
                $<INSTALL_INTERFACE:PipeHandler>
                $<INSTALL_INTERFACE:MemoryModule>
                $<INSTALL_INTERFACE:SocksServer>
                $<INSTALL_INTERFACE:dl>)
endif()
# add_custom_command(TARGET BeaconTcpLib POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
# $<TARGET_FILE:BeaconTcpLib> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconTcpLib>")


set(SOURCES_BEACON_SMB_EXE
	Beacon.cpp
	BeaconSmb.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)

add_library(BeaconSmbLib ${SOURCES_BEACON_SMB_EXE})
target_include_directories(BeaconSmbLib PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}> $<INSTALL_INTERFACE:include>)
if(WIN32)
        set_property(TARGET BeaconSmbLib PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
        target_link_libraries(BeaconSmbLib PUBLIC
                $<BUILD_INTERFACE:SocketHandler>
                $<BUILD_INTERFACE:PipeHandler>
                $<BUILD_INTERFACE:MemoryModule>
                $<BUILD_INTERFACE:SocksServer>
                $<INSTALL_INTERFACE:SocketHandler>
                $<INSTALL_INTERFACE:PipeHandler>
                $<INSTALL_INTERFACE:MemoryModule>
                $<INSTALL_INTERFACE:SocksServer>)
else()
        target_link_libraries(BeaconSmbLib PUBLIC
                $<BUILD_INTERFACE:SocketHandler>
                $<BUILD_INTERFACE:PipeHandler>
                $<BUILD_INTERFACE:MemoryModule>
                $<BUILD_INTERFACE:SocksServer>
                $<BUILD_INTERFACE:dl>
                $<INSTALL_INTERFACE:SocketHandler>
                $<INSTALL_INTERFACE:PipeHandler>
                $<INSTALL_INTERFACE:MemoryModule>
                $<INSTALL_INTERFACE:SocksServer>
                $<INSTALL_INTERFACE:dl>)
endif()
# add_custom_command(TARGET BeaconSmbLib POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
# $<TARGET_FILE:BeaconSmbLib> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconSmbLib>")


set(SOURCES_BEACON_GITHUB_EXE
	Beacon.cpp
	BeaconGithub.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)

add_library(BeaconGithubLib ${SOURCES_BEACON_GITHUB_EXE})
target_include_directories(BeaconGithubLib PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}> $<INSTALL_INTERFACE:include>)
if(WIN32)
        set_property(TARGET BeaconGithubLib PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
        target_link_libraries(BeaconGithubLib PUBLIC
                $<BUILD_INTERFACE:SocketHandler>
                $<BUILD_INTERFACE:PipeHandler>
                $<BUILD_INTERFACE:MemoryModule>
                $<BUILD_INTERFACE:SocksServer>
                $<INSTALL_INTERFACE:SocketHandler>
                $<INSTALL_INTERFACE:PipeHandler>
                $<INSTALL_INTERFACE:MemoryModule>
                $<INSTALL_INTERFACE:SocksServer>)
else()
        target_link_libraries(BeaconGithubLib PUBLIC
                $<BUILD_INTERFACE:SocketHandler>
                $<BUILD_INTERFACE:PipeHandler>
                $<BUILD_INTERFACE:MemoryModule>
                $<BUILD_INTERFACE:SocksServer>
                $<BUILD_INTERFACE:openssl::openssl>
                $<BUILD_INTERFACE:httplib::httplib>
                $<BUILD_INTERFACE:dl>
                $<INSTALL_INTERFACE:SocketHandler>
                $<INSTALL_INTERFACE:PipeHandler>
                $<INSTALL_INTERFACE:MemoryModule>
                $<INSTALL_INTERFACE:SocksServer>
                $<INSTALL_INTERFACE:openssl::openssl>
                $<INSTALL_INTERFACE:httplib::httplib>
                $<INSTALL_INTERFACE:dl>)
endif()
# add_custom_command(TARGET BeaconGithubLib POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
# $<TARGET_FILE:BeaconGithubLib> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconGithubLib>")


set(SOURCES_BEACON_DNS_EXE
	Beacon.cpp
	BeaconDns.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)


add_library(BeaconDnsLib ${SOURCES_BEACON_DNS_EXE})
target_include_directories(BeaconDnsLib PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}> $<INSTALL_INTERFACE:include>)

if(WIN32)
        set_property(TARGET BeaconDnsLib PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
        target_link_libraries(BeaconDnsLib PUBLIC
                $<BUILD_INTERFACE:Dnscommunication>
                $<BUILD_INTERFACE:SocketHandler>
                $<BUILD_INTERFACE:PipeHandler>
                $<BUILD_INTERFACE:MemoryModule>
                $<BUILD_INTERFACE:SocksServer>
                $<INSTALL_INTERFACE:Dnscommunication>
                $<INSTALL_INTERFACE:SocketHandler>
                $<INSTALL_INTERFACE:PipeHandler>
                $<INSTALL_INTERFACE:MemoryModule>
                $<INSTALL_INTERFACE:SocksServer>)
else()
        target_link_libraries(BeaconDnsLib PUBLIC
                $<BUILD_INTERFACE:Dnscommunication>
                $<BUILD_INTERFACE:SocketHandler>
                $<BUILD_INTERFACE:PipeHandler>
                $<BUILD_INTERFACE:MemoryModule>
                $<BUILD_INTERFACE:SocksServer>
                $<BUILD_INTERFACE:dl>
                $<INSTALL_INTERFACE:Dnscommunication>
                $<INSTALL_INTERFACE:SocketHandler>
                $<INSTALL_INTERFACE:PipeHandler>
                $<INSTALL_INTERFACE:MemoryModule>
                $<INSTALL_INTERFACE:SocksServer>
                $<INSTALL_INTERFACE:dl>)
endif()
# add_custom_command(TARGET BeaconDnsLib POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
# $<TARGET_FILE:BeaconDnsLib> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconDnsLib>")

install(TARGETS BeaconHttpLib BeaconTcpLib BeaconSmbLib BeaconGithubLib BeaconDnsLib
        SocketHandler PipeHandler MemoryModule SocksServer Dnscommunication
        EXPORT C2CoreTargets
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include)

