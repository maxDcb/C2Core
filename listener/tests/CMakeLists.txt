include_directories(..)
include_directories(../../modules/ModuleCmd)

if(BUILD_TEAMSERVER)
    set(additionalLib "spdlog::spdlog")
else()
    set(additionalLib "")
endif()

# Test testListener
add_executable(testListener testListener.cpp)
IF (WIN32)
    set_property(TARGET testListener PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_libraries(testListener ${additionalLib})
else()
	target_link_libraries(testListener ${additionalLib})
endif()
add_custom_command(TARGET testListener POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListener> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListener>")
add_test(NAME testListener COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListener>")

IF (WIN32)
ELSE()

    # Test testListenerDns
    add_executable(testListenerDns testListenerDns.cpp)
    IF (WIN32)
        set_property(TARGET testListenerDns PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
        target_link_libraries(testListenerDns Dnscommunication ${additionalLib})
    else()
        target_link_libraries(testListenerDns Dnscommunication ${additionalLib})
    endif()
    add_custom_command(TARGET testListenerDns POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testListenerDns> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerDns>")
    add_test(NAME testListenerDns COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerDns>")

    # Test testListenerGithub
    add_executable(testListenerGithub testListenerGithub.cpp)
    IF (WIN32)
        set_property(TARGET testListenerGithub PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
        target_link_libraries(testListenerGithub openssl::openssl ${additionalLib})
    else()
        target_link_libraries(testListenerGithub openssl::openssl httplib::httplib ${additionalLib})
    endif()
    add_custom_command(TARGET testListenerGithub POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testListenerGithub> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerGithub>")
    add_test(NAME testListenerGithub COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerGithub>")

    # Test testListenerHttp
    add_executable(testListenerHttp testListenerHttp.cpp)
    IF (WIN32)
        set_property(TARGET testListenerHttp PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
        target_link_libraries(testListenerHttp openssl::openssl ${additionalLib})
    else()
        target_link_libraries(testListenerHttp openssl::openssl httplib::httplib ${additionalLib})
    endif()
    add_custom_command(TARGET testListenerHttp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testListenerHttp> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerHttp>")
    add_test(NAME testListenerHttp COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerHttp>")

ENDIF()

# Test testListenerSmb
add_executable(testListenerSmb testListenerSmb.cpp)
IF (WIN32)
    set_property(TARGET testListenerSmb PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_libraries(testListenerSmb PipeHandler ${additionalLib})
else()
	target_link_libraries(testListenerSmb PipeHandler ${additionalLib})
endif()
add_custom_command(TARGET testListenerSmb POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListenerSmb> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerSmb>")
add_test(NAME testListenerSmb COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerSmb>")

# Test testListenerTcp
add_executable(testListenerTcp testListenerTcp.cpp)
IF (WIN32)
    set_property(TARGET testListenerTcp PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_libraries(testListenerTcp SocketHandler ${additionalLib})
else()
	target_link_libraries(testListenerTcp SocketHandler ${additionalLib})
endif()
add_custom_command(TARGET testListenerTcp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListenerTcp> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerTcp>")
add_test(NAME testListenerTcp COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerTcp>")

