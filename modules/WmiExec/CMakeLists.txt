include_directories(../)
add_library(WmiExec SHARED WmiExec.cpp)
set_property(TARGET WmiExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(WmiExec )
add_custom_command(TARGET WmiExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:WmiExec> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:WmiExec>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsWmiExec tests/testsWmiExec.cpp WmiExec.cpp)
    target_link_libraries(testsWmiExec PRIVATE c2_base64)
    target_link_libraries(testsWmiExec )
    add_custom_command(TARGET testsWmiExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsWmiExec> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsWmiExec>")

    add_test(NAME testsWmiExec COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsWmiExec>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_executable(testsWmiExecFunctional tests/functional/testsWmiExecFunctional.cpp WmiExec.cpp)
    target_link_libraries(testsWmiExecFunctional PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(testsWmiExecFunctional PRIVATE C2CORE_BUILD_FUNCTIONAL_TESTS)
    target_include_directories(testsWmiExecFunctional PRIVATE ../tests)
    target_link_libraries(testsWmiExecFunctional )
    add_custom_command(TARGET testsWmiExecFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsWmiExecFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsWmiExecFunctional>")

    add_test(NAME testsWmiExecFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsWmiExecFunctional>")
    set_tests_properties(testsWmiExecFunctional PROPERTIES LABELS "functional;wmi;windows-network" SKIP_RETURN_CODE 77)
endif()
