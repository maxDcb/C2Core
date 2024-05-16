include_directories(../modules/ModuleCmd)

set(SOURCES_BEACON_HTTP_EXE
	Beacon.cpp
	BeaconHttp.cpp
	BeaconHttpLauncher.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)

add_executable(BeaconHttp ${SOURCES_BEACON_HTTP_EXE} project.rc)
if(WIN32)
	target_link_libraries(BeaconHttp SocketHandler PipeHandler MemoryModule spdlog::spdlog nlohmann_json::nlohmann_json)
else()
	target_link_libraries(BeaconHttp SocketHandler PipeHandler MemoryModule openssl::openssl boost::boost spdlog::spdlog nlohmann_json::nlohmann_json)
endif()
add_custom_command(TARGET BeaconHttp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:BeaconHttp> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconHttp>")


set(SOURCES_BEACON_HTTP_DLL
	Beacon.cpp
	BeaconHttp.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)

add_library(BeaconHttpDll SHARED ${SOURCES_BEACON_HTTP_DLL})
if(WIN32)
	target_link_libraries(BeaconHttpDll SocketHandler PipeHandler MemoryModule spdlog::spdlog nlohmann_json::nlohmann_json)
else()
	target_link_libraries(BeaconHttpDll SocketHandler PipeHandler MemoryModule openssl::openssl boost::boost spdlog::spdlog nlohmann_json::nlohmann_json)
endif()
add_custom_command(TARGET BeaconHttpDll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:BeaconHttpDll> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconHttpDll>")


set(SOURCES_BEACON_TCP_EXE
	Beacon.cpp
	BeaconTcp.cpp
	BeaconTcpLauncher.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)

add_executable(BeaconTcp ${SOURCES_BEACON_TCP_EXE})
if(WIN32)
	target_link_libraries(BeaconTcp SocketHandler PipeHandler MemoryModule spdlog::spdlog nlohmann_json::nlohmann_json)
else()
	target_link_libraries(BeaconTcp SocketHandler PipeHandler MemoryModule boost::boost spdlog::spdlog nlohmann_json::nlohmann_json)
endif()
add_custom_command(TARGET BeaconTcp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:BeaconTcp> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconTcp>")


set(SOURCES_BEACON_SMB_EXE
	Beacon.cpp
	BeaconSmb.cpp
	BeaconSmbLauncher.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)

add_executable(BeaconSmb ${SOURCES_BEACON_SMB_EXE})
if(WIN32)
	target_link_libraries(BeaconSmb SocketHandler PipeHandler MemoryModule spdlog::spdlog nlohmann_json::nlohmann_json)
else()
	target_link_libraries(BeaconSmb SocketHandler PipeHandler MemoryModule boost::boost spdlog::spdlog nlohmann_json::nlohmann_json)
endif()
add_custom_command(TARGET BeaconSmb POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:BeaconSmb> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconSmb>")


set(SOURCES_BEACON_GITHUB_EXE
	Beacon.cpp
	BeaconGithub.cpp
	BeaconGithubLauncher.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)

add_executable(BeaconGithub ${SOURCES_BEACON_GITHUB_EXE})
if(WIN32)
	target_link_libraries(BeaconGithub SocketHandler PipeHandler MemoryModule spdlog::spdlog nlohmann_json::nlohmann_json)
else()
	target_link_libraries(BeaconGithub SocketHandler PipeHandler MemoryModule openssl::openssl boost::boost spdlog::spdlog nlohmann_json::nlohmann_json)
endif()
add_custom_command(TARGET BeaconGithub POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:BeaconGithub> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconGithub>")


set(SOURCES_BEACON_DNS_EXE
	Beacon.cpp
	BeaconDns.cpp
	BeaconDnsLauncher.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../../thirdParty/base64/base64.cpp
)

add_executable(BeaconDns ${SOURCES_BEACON_DNS_EXE})
if(WIN32)
	target_link_libraries(BeaconDns Dnscommunication SocketHandler PipeHandler MemoryModule spdlog::spdlog nlohmann_json::nlohmann_json)
else()
	target_link_libraries(BeaconDns Dnscommunication SocketHandler PipeHandler MemoryModule boost::boost spdlog::spdlog nlohmann_json::nlohmann_json)
endif()
add_custom_command(TARGET BeaconDns POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:BeaconDns> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconDns>")
