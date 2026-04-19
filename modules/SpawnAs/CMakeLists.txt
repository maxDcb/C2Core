include_directories(../)
add_library(SpawnAs SHARED SpawnAs.cpp)
set_property(TARGET SpawnAs PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(SpawnAs ${Donut} )

if(WIN32)
    target_link_libraries(SpawnAs advapi32 userenv)
endif()
add_custom_command(TARGET SpawnAs POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:SpawnAs> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:SpawnAs>")

if(C2CORE_BUILD_TESTS)
add_executable(testsSpawnAs tests/testsSpawnAs.cpp SpawnAs.cpp)

if(WIN32)
    target_link_libraries(testsSpawnAs ${Donut} advapi32 userenv)
else()
    target_link_libraries(testsSpawnAs ${Donut} ${aplib64} )
endif()

add_custom_command(TARGET testsSpawnAs POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsSpawnAs> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsSpawnAs>")

add_test(NAME testsSpawnAs COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsSpawnAs>")
endif()