include_directories(..)
include_directories(../..)
include_directories(../../listener)
include_directories(../../modules/ModuleCmd)

set(C2CORE_BEACON_TEST_HTTP_LINK_LIBS)

if(NOT WIN32)
    list(APPEND C2CORE_BEACON_TEST_HTTP_LINK_LIBS
        openssl::openssl
        httplib::httplib)
endif()

add_executable(beacon_unit_tests
    testBeacon.cpp
    ../Beacon.cpp
    ../../listener/Listener.cpp
    ../../listener/ListenerTcp.cpp
    ../../listener/ListenerSmb.cpp)

target_link_libraries(beacon_unit_tests
    nlohmann_json::nlohmann_json
    SocketHandler
    PipeHandler
    MemoryModule
    SocksServer
    c2_base64)

add_test(NAME beacon_unit_tests COMMAND beacon_unit_tests)

# Manual smoke executables for transport variants. They are built with the test
# suite but are not registered in CTest because they only validate construction.
add_executable(testBeaconDns
    testBeaconDns.cpp
    ../Beacon.cpp
    ../BeaconDns.cpp
    ../../listener/Listener.cpp
    ../../listener/ListenerTcp.cpp
    ../../listener/ListenerSmb.cpp)

target_link_libraries(testBeaconDns
    nlohmann_json::nlohmann_json
    SocketHandler
    Dnscommunication
    PipeHandler
    MemoryModule
    SocksServer
    c2_base64)

add_executable(testBeaconGithub
    testBeaconGithub.cpp
    ../Beacon.cpp
    ../BeaconGithub.cpp
    ../../listener/Listener.cpp
    ../../listener/ListenerTcp.cpp
    ../../listener/ListenerSmb.cpp)

target_link_libraries(testBeaconGithub
    nlohmann_json::nlohmann_json
    SocketHandler
    PipeHandler
    MemoryModule
    SocksServer
    c2_base64
    ${C2CORE_BEACON_TEST_HTTP_LINK_LIBS})

add_executable(testBeaconHttp
    testBeaconHttp.cpp
    ../Beacon.cpp
    ../BeaconHttp.cpp
    ../../listener/Listener.cpp
    ../../listener/ListenerTcp.cpp
    ../../listener/ListenerSmb.cpp)

target_link_libraries(testBeaconHttp
    nlohmann_json::nlohmann_json
    SocketHandler
    PipeHandler
    MemoryModule
    SocksServer
    c2_base64
    ${C2CORE_BEACON_TEST_HTTP_LINK_LIBS})

add_executable(testBeaconSmb
    testBeaconSmb.cpp
    ../Beacon.cpp
    ../BeaconSmb.cpp
    ../../listener/Listener.cpp
    ../../listener/ListenerTcp.cpp
    ../../listener/ListenerSmb.cpp)

target_link_libraries(testBeaconSmb
    nlohmann_json::nlohmann_json
    SocketHandler
    PipeHandler
    MemoryModule
    SocksServer
    c2_base64)

add_executable(testBeaconTcp
    testBeaconTcp.cpp
    ../Beacon.cpp
    ../BeaconTcp.cpp
    ../../listener/Listener.cpp
    ../../listener/ListenerTcp.cpp
    ../../listener/ListenerSmb.cpp)

target_link_libraries(testBeaconTcp
    nlohmann_json::nlohmann_json
    SocketHandler
    PipeHandler
    MemoryModule
    SocksServer
    c2_base64)

