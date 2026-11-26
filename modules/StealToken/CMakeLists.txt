include_directories(../)
add_library(StealToken SHARED StealToken.cpp)
set_property(TARGET StealToken PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(StealToken )
add_custom_command(TARGET StealToken POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:StealToken> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:StealToken>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsStealToken tests/testsStealToken.cpp StealToken.cpp)
    target_link_libraries(testsStealToken PRIVATE c2_base64)
    add_custom_command(TARGET testsStealToken POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsStealToken> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsStealToken>")

    add_test(NAME testsStealToken COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsStealToken>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_executable(testsStealTokenFunctional tests/functional/testsStealTokenFunctional.cpp StealToken.cpp)
    target_include_directories(testsStealTokenFunctional PRIVATE ../tests)
    target_link_libraries(testsStealTokenFunctional PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(testsStealTokenFunctional PRIVATE C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_custom_command(TARGET testsStealTokenFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsStealTokenFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsStealTokenFunctional>")
    add_test(NAME testsStealTokenFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsStealTokenFunctional>")
    set_tests_properties(testsStealTokenFunctional PROPERTIES LABELS "functional;stealtoken;windows-local" SKIP_RETURN_CODE 77)
endif()
