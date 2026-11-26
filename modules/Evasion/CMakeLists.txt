include_directories(../)
add_library(Evasion SHARED Evasion.cpp)
set_property(TARGET Evasion PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Evasion )
add_custom_command(TARGET Evasion POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Evasion> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Evasion>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsEvasion tests/testsEvasion.cpp Evasion.cpp)
    target_link_libraries(testsEvasion )
    add_custom_command(TARGET testsEvasion POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsEvasion> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsEvasion>")

    add_test(NAME testsEvasion COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsEvasion>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_executable(testsEvasionFunctional tests/functional/testsEvasionFunctional.cpp Evasion.cpp)
    target_include_directories(testsEvasionFunctional PRIVATE ../tests)
    target_link_libraries(testsEvasionFunctional PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(testsEvasionFunctional PRIVATE C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_custom_command(TARGET testsEvasionFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsEvasionFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsEvasionFunctional>")

    add_test(NAME testsEvasionFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsEvasionFunctional>")
    set_tests_properties(testsEvasionFunctional PROPERTIES LABELS "functional;evasion;windows-local" SKIP_RETURN_CODE 77)
endif()
