include_directories(..)
include_directories(../..)
include_directories(../../listener)
include_directories(../../modules/ModuleCmd)

set(C2CORE_BEACON_TEST_HTTP_LINK_LIBS)
set(C2CORE_BEACON_TEST_LOG_LIBS)

if(BUILD_TEAMSERVER)
    list(APPEND C2CORE_BEACON_TEST_LOG_LIBS spdlog::spdlog)
endif()

if(NOT WIN32)
    list(APPEND C2CORE_BEACON_TEST_HTTP_LINK_LIBS
        openssl::openssl
        httplib::httplib)
endif()

if(C2CORE_BUILD_TESTS)
    add_executable(beacon_unit_tests
        testBeacon.cpp
        ../Beacon.cpp
        ../../listener/Listener.cpp
        ../../listener/ListenerTcp.cpp
        ../../listener/ListenerSmb.cpp)

    target_link_libraries(beacon_unit_tests
        nlohmann_json::nlohmann_json
        ${C2CORE_BEACON_TEST_LOG_LIBS}
        SocketHandler
        PipeHandler
        MemoryModule
        SocksServer
        c2_base64)

    add_test(NAME beacon_unit_tests COMMAND beacon_unit_tests)
endif()

# Transport executables share the core beacon sources. The TCP variant exercises
# a real listener/beacon exchange and is registered in the regular test suite.
if(C2CORE_BUILD_TESTS OR C2CORE_BUILD_FUNCTIONAL_TESTS)
add_executable(testBeaconDns
    testBeaconDns.cpp
    ../Beacon.cpp
    ../BeaconDns.cpp
    ../../listener/Listener.cpp
    ../../listener/ListenerTcp.cpp
    ../../listener/ListenerSmb.cpp)

target_link_libraries(testBeaconDns
    nlohmann_json::nlohmann_json
    ${C2CORE_BEACON_TEST_LOG_LIBS}
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
    ${C2CORE_BEACON_TEST_LOG_LIBS}
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
    ${C2CORE_BEACON_TEST_LOG_LIBS}
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
    ${C2CORE_BEACON_TEST_LOG_LIBS}
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
    ${C2CORE_BEACON_TEST_LOG_LIBS}
    SocketHandler
    PipeHandler
    MemoryModule
    SocksServer
    c2_base64)

if(C2CORE_BUILD_TESTS)
    add_test(NAME beacon_tcp_contract_tests COMMAND testBeaconTcp)
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_test(NAME testBeaconDnsFunctional COMMAND testBeaconDns)
    add_test(NAME testBeaconGithubFunctional COMMAND testBeaconGithub)
    add_test(NAME testBeaconHttpFunctional COMMAND testBeaconHttp)
    add_test(NAME testBeaconSmbFunctional COMMAND testBeaconSmb)
    add_test(NAME testBeaconTcpFunctional COMMAND testBeaconTcp)
    set_tests_properties(
        testBeaconDnsFunctional
        testBeaconGithubFunctional
        testBeaconHttpFunctional
        testBeaconSmbFunctional
        testBeaconTcpFunctional
        PROPERTIES LABELS "functional;transport;beacon")
endif()
endif()

