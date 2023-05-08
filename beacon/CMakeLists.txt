include_directories(../modules/ModuleCmd)

set(SOURCES_BEACON_HTTP_EXE
	Beacon.cpp
	BeaconHttp.cpp
	BeaconHttpLauncher.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../modules/ModuleCmd/ModuleCmd.cpp
	../../thirdParty/base64/base64.cpp
)

add_executable(BeaconHttp ${SOURCES_BEACON_HTTP_EXE})
target_link_libraries(BeaconHttp SocketHandler PipeHandler MemoryModule)
add_custom_command(TARGET BeaconHttp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:BeaconHttp> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconHttp>")


set(SOURCES_BEACON_HTTP_DLL
	Beacon.cpp
	BeaconHttp.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../modules/ModuleCmd/ModuleCmd.cpp
	../../thirdParty/base64/base64.cpp
)

add_library(BeaconHttpDll SHARED ${SOURCES_BEACON_HTTP_DLL})
target_link_libraries(BeaconHttpDll SocketHandler PipeHandler MemoryModule)
add_custom_command(TARGET BeaconHttpDll POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:BeaconHttpDll> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconHttpDll>")


set(SOURCES_BEACON_TCP_EXE
	Beacon.cpp
	BeaconTcp.cpp
	BeaconTcpLauncher.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../modules/ModuleCmd/ModuleCmd.cpp
	../../thirdParty/base64/base64.cpp
)

add_executable(BeaconTcp ${SOURCES_BEACON_TCP_EXE})
target_link_libraries(BeaconTcp SocketHandler PipeHandler MemoryModule)
add_custom_command(TARGET BeaconTcp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:BeaconTcp> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconTcp>")


set(SOURCES_BEACON_SMB_EXE
	Beacon.cpp
	BeaconSmb.cpp
	BeaconSmbLauncher.cpp
	../listener/Listener.cpp
	../listener/ListenerTcp.cpp	
	../listener/ListenerSmb.cpp	
	../modules/ModuleCmd/ModuleCmd.cpp
	../../thirdParty/base64/base64.cpp
)

add_executable(BeaconSmb ${SOURCES_BEACON_SMB_EXE})
target_link_libraries(BeaconSmb SocketHandler PipeHandler MemoryModule)
add_custom_command(TARGET BeaconSmb POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:BeaconSmb> "${CMAKE_SOURCE_DIR}/Release/Beacons/$<TARGET_FILE_NAME:BeaconSmb>")

