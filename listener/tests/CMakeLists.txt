include_directories(..)
include_directories(../../modules/ModuleCmd)
include_directories(../../thirdParty/base64)

if(BUILD_TEAMSERVER)
    set(additionalLib "spdlog::spdlog")
else()
    set(additionalLib "")
endif()

# Unit tests using Catch2
add_executable(listener_unit_tests
    testListener.cpp
    ../Listener.cpp
    ../../thirdParty/base64/base64.cpp)

target_link_libraries(listener_unit_tests
    Catch2::Catch2WithMain
    Catch2::Catch2
    nlohmann_json::nlohmann_json
    ${additionalLib})

add_test(NAME listener_unit_tests COMMAND listener_unit_tests)

# Functional tests for transport variants (simple main)
add_executable(testListenerDns
    testListenerDns.cpp
    ../Listener.cpp
    ../ListenerDns.cpp
    ../../thirdParty/base64/base64.cpp)
target_link_libraries(testListenerDns nlohmann_json::nlohmann_json Dnscommunication ${additionalLib})
add_test(NAME testListenerDns COMMAND testListenerDns)

add_executable(testListenerGithub
    testListenerGithub.cpp
    ../Listener.cpp
    ../ListenerGithub.cpp
    ../../thirdParty/base64/base64.cpp)
target_link_libraries(testListenerGithub nlohmann_json::nlohmann_json openssl::openssl httplib::httplib ${additionalLib})
add_test(NAME testListenerGithub COMMAND testListenerGithub)


add_executable(testListenerSmb
    testListenerSmb.cpp
    ../Listener.cpp
    ../ListenerSmb.cpp
    ../../thirdParty/base64/base64.cpp)
target_link_libraries(testListenerSmb nlohmann_json::nlohmann_json PipeHandler ${additionalLib})
add_test(NAME testListenerSmb COMMAND testListenerSmb)

add_executable(testListenerTcp
    testListenerTcp.cpp
    ../Listener.cpp
    ../ListenerTcp.cpp
    ../../thirdParty/base64/base64.cpp)
target_link_libraries(testListenerTcp nlohmann_json::nlohmann_json SocketHandler ${additionalLib})
add_test(NAME testListenerTcp COMMAND testListenerTcp)
