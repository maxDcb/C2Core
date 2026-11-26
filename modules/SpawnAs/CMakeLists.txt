include_directories(../)
add_library(SpawnAs SHARED SpawnAs.cpp)
set_property(TARGET SpawnAs PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

if(WIN32)
    target_link_libraries(SpawnAs advapi32 userenv)
endif()
add_custom_command(TARGET SpawnAs POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:SpawnAs> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:SpawnAs>")

if(C2CORE_BUILD_TESTS)
add_executable(testsSpawnAs tests/testsSpawnAs.cpp SpawnAs.cpp)

if(WIN32)
    target_link_libraries(testsSpawnAs advapi32 userenv)
else()
    target_link_libraries(testsSpawnAs ${aplib64} )
endif()

add_custom_command(TARGET testsSpawnAs POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsSpawnAs> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsSpawnAs>")

add_test(NAME testsSpawnAs COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsSpawnAs>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
add_executable(testsSpawnAsFunctional tests/functional/testsSpawnAsFunctional.cpp SpawnAs.cpp)
target_include_directories(testsSpawnAsFunctional PRIVATE ../tests)
target_compile_definitions(testsSpawnAsFunctional PRIVATE C2CORE_BUILD_FUNCTIONAL_TESTS)
target_link_libraries(testsSpawnAsFunctional c2_base64 nlohmann_json::nlohmann_json)

if(WIN32)
    target_link_libraries(testsSpawnAsFunctional advapi32 userenv)
else()
    target_link_libraries(testsSpawnAsFunctional ${aplib64} )
endif()

add_custom_command(TARGET testsSpawnAsFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
$<TARGET_FILE:testsSpawnAsFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsSpawnAsFunctional>")

add_test(NAME testsSpawnAsFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsSpawnAsFunctional>")
set_tests_properties(testsSpawnAsFunctional PROPERTIES LABELS "functional;spawnas;windows-local" SKIP_RETURN_CODE 77)
endif()
