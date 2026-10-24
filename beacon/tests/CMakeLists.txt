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
    ../../listener/ListenerDns.cpp
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

if(C2_ENABLE_GITHUB_TRANSPORT)
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
endif()

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

if(WIN32)
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
endif()

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
    add_test(NAME beacon_http_delivery_tests COMMAND testBeaconHttp)
    if(WIN32)
        add_test(NAME beacon_smb_contract_tests COMMAND testBeaconSmb)
        set_tests_properties(beacon_smb_contract_tests PROPERTIES TIMEOUT 45)
    endif()
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_test(NAME testBeaconDnsFunctional COMMAND testBeaconDns)
    set_tests_properties(testBeaconDnsFunctional PROPERTIES TIMEOUT 60)
    if(C2_ENABLE_GITHUB_TRANSPORT)
        add_test(NAME testBeaconGithubFunctional COMMAND testBeaconGithub)
        set_tests_properties(testBeaconGithubFunctional PROPERTIES LABELS "functional;transport;beacon")
    endif()
    add_test(NAME testBeaconHttpFunctional COMMAND testBeaconHttp)
    if(WIN32)
        add_test(NAME testBeaconSmbFunctional COMMAND testBeaconSmb)
        set_tests_properties(testBeaconSmbFunctional PROPERTIES LABELS "functional;transport;beacon")
    endif()
    add_test(NAME testBeaconTcpFunctional COMMAND testBeaconTcp)
    set_tests_properties(
        testBeaconDnsFunctional
        testBeaconHttpFunctional
        testBeaconTcpFunctional
        PROPERTIES LABELS "functional;transport;beacon")
endif()
endif()

