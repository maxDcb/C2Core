include_directories(..)
include_directories(../../modules/ModuleCmd)

IF (WIN32)
ELSE()
    include_directories(${Boost_INCLUDE_DIRS})
ENDIF()

add_executable(testListener testListener.cpp)
if(WIN32)
    target_link_libraries(testListener spdlog::spdlog nlohmann_json::nlohmann_json)
else()
	target_link_libraries(testListener spdlog::spdlog nlohmann_json::nlohmann_json)
endif()
add_custom_command(TARGET testListener POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListener> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListener>")
add_test(NAME testListener COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListener>")

IF (WIN32)
ELSE()

add_executable(testListenerDns testListenerDns.cpp)
if(WIN32)
    target_link_libraries(testListenerDns Dnscommunication spdlog::spdlog nlohmann_json::nlohmann_json)
else()
	target_link_libraries(testListenerDns Dnscommunication spdlog::spdlog nlohmann_json::nlohmann_json)
endif()
add_custom_command(TARGET testListenerDns POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListenerDns> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerDns>")
add_test(NAME testListenerDns COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerDns>")

add_executable(testListenerGithub testListenerGithub.cpp)
if(WIN32)
    target_link_libraries(testListenerGithub openssl::openssl spdlog::spdlog nlohmann_json::nlohmann_json)
else()
	target_link_libraries(testListenerGithub openssl::openssl spdlog::spdlog nlohmann_json::nlohmann_json)
endif()
add_custom_command(TARGET testListenerGithub POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListenerGithub> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerGithub>")
add_test(NAME testListenerGithub COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerGithub>")

add_executable(testListenerHttp testListenerHttp.cpp)
if(WIN32)
    target_link_libraries(testListenerHttp openssl::openssl spdlog::spdlog nlohmann_json::nlohmann_json)
else()
	target_link_libraries(testListenerHttp openssl::openssl spdlog::spdlog nlohmann_json::nlohmann_json)
endif()
add_custom_command(TARGET testListenerHttp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListenerHttp> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerHttp>")
add_test(NAME testListenerHttp COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerHttp>")

ENDIF()

add_executable(testListenerSmb testListenerSmb.cpp)
if(WIN32)
    target_link_libraries(testListenerSmb PipeHandler spdlog::spdlog nlohmann_json::nlohmann_json)
else()
	target_link_libraries(testListenerSmb PipeHandler spdlog::spdlog nlohmann_json::nlohmann_json)
endif()
add_custom_command(TARGET testListenerSmb POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListenerSmb> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerSmb>")
add_test(NAME testListenerSmb COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerSmb>")

add_executable(testListenerTcp testListenerTcp.cpp)
if(WIN32)
    target_link_libraries(testListenerTcp SocketHandler spdlog::spdlog nlohmann_json::nlohmann_json)
else()
	target_link_libraries(testListenerTcp SocketHandler spdlog::spdlog nlohmann_json::nlohmann_json)
endif()
add_custom_command(TARGET testListenerTcp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListenerTcp> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerTcp>")
add_test(NAME testListenerTcp COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerTcp>")

