include_directories(..)
include_directories(../../modules/ModuleCmd)

# Unit tests using Catch2
add_executable(beacon_unit_tests
    testBeacon.cpp
    ../Beacon.cpp
    ../../listener/Listener.cpp
    ../../listener/ListenerTcp.cpp
    ../../listener/ListenerSmb.cpp
    ../../../thirdParty/base64/base64.cpp)

target_link_libraries(beacon_unit_tests
    Catch2::Catch2WithMain
    Catch2::Catch2
    nlohmann_json::nlohmann_json
    SocketHandler
    PipeHandler
    MemoryModule
    SocksServer)

add_test(NAME beacon_unit_tests COMMAND beacon_unit_tests)

# Functional tests for transport variants (simple main)
add_executable(testBeaconDns
    testBeaconDns.cpp
    ../Beacon.cpp
    ../BeaconDns.cpp
    ../../listener/Listener.cpp
    ../../listener/ListenerTcp.cpp
    ../../listener/ListenerSmb.cpp
    ../../../thirdParty/base64/base64.cpp)

target_link_libraries(testBeaconDns
    nlohmann_json::nlohmann_json
    SocketHandler
    Dnscommunication
    PipeHandler
    MemoryModule
    SocksServer)

add_test(NAME testBeaconDns COMMAND testBeaconDns)

add_executable(testBeaconGithub
    testBeaconGithub.cpp
    ../Beacon.cpp
    ../BeaconGithub.cpp
    ../../listener/Listener.cpp
    ../../listener/ListenerTcp.cpp
    ../../listener/ListenerSmb.cpp
    ../../../thirdParty/base64/base64.cpp)

target_link_libraries(testBeaconGithub
    nlohmann_json::nlohmann_json
    SocketHandler
    PipeHandler
    MemoryModule
    SocksServer
    httplib::httplib)

add_test(NAME testBeaconGithub COMMAND testBeaconGithub)

add_executable(testBeaconHttp
    testBeaconHttp.cpp
    ../Beacon.cpp
    ../BeaconHttp.cpp
    ../../listener/Listener.cpp
    ../../listener/ListenerTcp.cpp
    ../../listener/ListenerSmb.cpp
    ../../../thirdParty/base64/base64.cpp)

target_link_libraries(testBeaconHttp
    nlohmann_json::nlohmann_json
    SocketHandler
    PipeHandler
    MemoryModule
    SocksServer
    httplib::httplib)

add_test(NAME testBeaconHttp COMMAND testBeaconHttp)

add_executable(testBeaconSmb
    testBeaconSmb.cpp
    ../Beacon.cpp
    ../BeaconSmb.cpp
    ../../listener/Listener.cpp
    ../../listener/ListenerTcp.cpp
    ../../listener/ListenerSmb.cpp
    ../../../thirdParty/base64/base64.cpp)

target_link_libraries(testBeaconSmb
    nlohmann_json::nlohmann_json
    SocketHandler
    PipeHandler
    MemoryModule
    SocksServer)

add_test(NAME testBeaconSmb COMMAND testBeaconSmb)

add_executable(testBeaconTcp
    testBeaconTcp.cpp
    ../Beacon.cpp
    ../BeaconTcp.cpp
    ../../listener/Listener.cpp
    ../../listener/ListenerTcp.cpp
    ../../listener/ListenerSmb.cpp
    ../../../thirdParty/base64/base64.cpp)

target_link_libraries(testBeaconTcp
    nlohmann_json::nlohmann_json
    SocketHandler
    PipeHandler
    MemoryModule
    SocksServer)

add_test(NAME testBeaconTcp COMMAND testBeaconTcp)
