include_directories(../)
add_library(Rev2self SHARED Rev2self.cpp)
set_property(TARGET Rev2self PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Rev2self )
add_custom_command(TARGET Rev2self POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Rev2self> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Rev2self>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsRev2self tests/testsRev2self.cpp Rev2self.cpp)
    target_link_libraries(testsRev2self PRIVATE c2_base64)
    add_custom_command(TARGET testsRev2self POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsRev2self> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsRev2self>")

    add_test(NAME testsRev2self COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsRev2self>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_executable(testsRev2selfFunctional tests/functional/testsRev2selfFunctional.cpp Rev2self.cpp ../StealToken/StealToken.cpp)
    target_include_directories(testsRev2selfFunctional PRIVATE ../tests)
    target_link_libraries(testsRev2selfFunctional PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(testsRev2selfFunctional PRIVATE C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_custom_command(TARGET testsRev2selfFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsRev2selfFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsRev2selfFunctional>")
    add_test(NAME testsRev2selfFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsRev2selfFunctional>")
    set_tests_properties(testsRev2selfFunctional PROPERTIES LABELS "functional;rev2self;windows-local" SKIP_RETURN_CODE 77)
endif()
