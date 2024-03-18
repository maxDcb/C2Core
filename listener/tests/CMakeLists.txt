include_directories(..)
include_directories(../../modules/ModuleCmd)



add_executable(testListener testListener.cpp)
add_custom_command(TARGET testListener POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListener> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListener>")
add_test(NAME testListener COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListener>")

add_executable(testListenerDns testListenerDns.cpp)
add_custom_command(TARGET testListenerDns POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListenerDns> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerDns>")
add_test(NAME testListenerDns COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerDns>")

add_executable(testListenerGithub testListenerGithub.cpp)
target_link_libraries(testListenerGithub openssl::openssl)
add_custom_command(TARGET testListenerGithub POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListenerGithub> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerGithub>")
add_test(NAME testListenerGithub COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerGithub>")

add_executable(testListenerHttp testListenerHttp.cpp)
target_link_libraries(testListenerHttp openssl::openssl)
add_custom_command(TARGET testListenerHttp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListenerHttp> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerHttp>")
add_test(NAME testListenerHttp COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerHttp>")

add_executable(testListenerSmb testListenerSmb.cpp)
target_link_libraries(testListenerSmb PipeHandler)
add_custom_command(TARGET testListenerSmb POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListenerSmb> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerSmb>")
add_test(NAME testListenerSmb COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerSmb>")

add_executable(testListenerTcp testListenerTcp.cpp)
add_custom_command(TARGET testListenerTcp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testListenerTcp> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerTcp>")
add_test(NAME testListenerTcp COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testListenerTcp>")

