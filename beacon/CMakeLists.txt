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
if(WIN32)
	set_property(TARGET BeaconHttpLib PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
	target_link_libraries(BeaconHttpLib SocketHandler PipeHandler MemoryModule SocksServer )
else()
	target_link_libraries(BeaconHttpLib SocketHandler PipeHandler MemoryModule SocksServer openssl::openssl httplib::httplib)
endif()


set(SOURCES_BEACON_TCP_EXE
	Beacon.cpp
	BeaconTcp.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)

add_library(BeaconTcpLib ${SOURCES_BEACON_TCP_EXE})
if(WIN32)
	set_property(TARGET BeaconTcpLib PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
	target_link_libraries(BeaconTcpLib SocketHandler PipeHandler MemoryModule SocksServer )
else()
	target_link_libraries(BeaconTcpLib SocketHandler PipeHandler MemoryModule SocksServer )
endif()


set(SOURCES_BEACON_SMB_EXE
	Beacon.cpp
	BeaconSmb.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)

add_library(BeaconSmbLib ${SOURCES_BEACON_SMB_EXE})
if(WIN32)
	set_property(TARGET BeaconSmbLib PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
	target_link_libraries(BeaconSmbLib SocketHandler PipeHandler MemoryModule SocksServer )
else()
	target_link_libraries(BeaconSmbLib SocketHandler PipeHandler MemoryModule SocksServer )
endif()


set(SOURCES_BEACON_GITHUB_EXE
	Beacon.cpp
	BeaconGithub.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)

add_library(BeaconGithubLib ${SOURCES_BEACON_GITHUB_EXE})
if(WIN32)
	set_property(TARGET BeaconGithubLib PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
	target_link_libraries(BeaconGithubLib SocketHandler PipeHandler MemoryModule SocksServer )
else()
	target_link_libraries(BeaconGithubLib SocketHandler PipeHandler MemoryModule SocksServer openssl::openssl  httplib::httplib)
endif()


set(SOURCES_BEACON_DNS_EXE
	Beacon.cpp
	BeaconDns.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)

add_library(BeaconDnsLib ${SOURCES_BEACON_DNS_EXE})
if(WIN32)
	set_property(TARGET BeaconDnsLib PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
	target_link_libraries(BeaconDnsLib Dnscommunication SocketHandler PipeHandler MemoryModule SocksServer )
else()
	target_link_libraries(BeaconDnsLib Dnscommunication SocketHandler PipeHandler MemoryModule SocksServer )
endif()
