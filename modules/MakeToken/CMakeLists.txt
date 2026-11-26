include_directories(../)
add_library(MakeToken SHARED MakeToken.cpp)
set_property(TARGET MakeToken PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(MakeToken )
add_custom_command(TARGET MakeToken POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:MakeToken> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:MakeToken>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsMakeToken tests/testsMakeToken.cpp MakeToken.cpp)
    target_link_libraries(testsMakeToken PRIVATE c2_base64)
    add_custom_command(TARGET testsMakeToken POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsMakeToken> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsMakeToken>")

    add_test(NAME testsMakeToken COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsMakeToken>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_executable(testsMakeTokenFunctional tests/functional/testsMakeTokenFunctional.cpp MakeToken.cpp)
    target_include_directories(testsMakeTokenFunctional PRIVATE ../tests)
    target_link_libraries(testsMakeTokenFunctional PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(testsMakeTokenFunctional PRIVATE C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_custom_command(TARGET testsMakeTokenFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsMakeTokenFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsMakeTokenFunctional>")
    add_test(NAME testsMakeTokenFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsMakeTokenFunctional>")
    set_tests_properties(testsMakeTokenFunctional PROPERTIES LABELS "functional;maketoken;windows-local" SKIP_RETURN_CODE 77)
endif()
