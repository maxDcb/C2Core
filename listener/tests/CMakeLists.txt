include_directories(..)
include_directories(../../modules/ModuleCmd)

if(BUILD_TEAMSERVER)
    set(additionalLib "spdlog::spdlog")
else()
    set(additionalLib "")
endif()

add_executable(listener_unit_tests
    testListener.cpp
    ../Listener.cpp)

target_link_libraries(listener_unit_tests
    nlohmann_json::nlohmann_json
    c2_base64
    ${additionalLib})

add_test(NAME listener_unit_tests COMMAND listener_unit_tests)

# Manual smoke executables for transport variants. They are built with the test
# suite but are not registered in CTest because they only validate construction.
add_executable(testListenerDns
    testListenerDns.cpp
    ../Listener.cpp
    ../ListenerDns.cpp)
target_link_libraries(testListenerDns nlohmann_json::nlohmann_json Dnscommunication c2_base64 ${additionalLib})

if(TARGET httplib::httplib)
    add_executable(testListenerGithub
        testListenerGithub.cpp
        ../Listener.cpp
        ../ListenerGithub.cpp)
    target_link_libraries(testListenerGithub nlohmann_json::nlohmann_json c2_base64 httplib::httplib ${additionalLib})
    if(TARGET openssl::openssl)
        target_link_libraries(testListenerGithub openssl::openssl)
    endif()
endif()


add_executable(testListenerSmb
    testListenerSmb.cpp
    ../Listener.cpp
    ../ListenerSmb.cpp)
target_link_libraries(testListenerSmb nlohmann_json::nlohmann_json PipeHandler c2_base64 ${additionalLib})

add_executable(testListenerTcp
    testListenerTcp.cpp
    ../Listener.cpp
    ../ListenerTcp.cpp)
target_link_libraries(testListenerTcp nlohmann_json::nlohmann_json SocketHandler c2_base64 ${additionalLib})
