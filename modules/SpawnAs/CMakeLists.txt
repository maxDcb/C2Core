include_directories(../)
add_library(SpawnAs SHARED SpawnAs.cpp)
set_property(TARGET SpawnAs PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(SpawnAs ${Donut} )
add_custom_command(TARGET SpawnAs POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:SpawnAs> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:SpawnAs>")

if(WITH_TESTS)
add_executable(testsSpawnAs tests/testsSpawnAs.cpp SpawnAs.cpp)

if(WIN32)
    target_link_libraries(testsSpawnAs ${Donut} )
else()
    target_link_libraries(testsSpawnAs ${Donut} ${aplib64} )
endif()

add_custom_command(TARGET testsSpawnAs POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsSpawnAs> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsSpawnAs>")

add_test(NAME testsSpawnAs COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsSpawnAs>")
endif()