include_directories(../)
add_library(CimExec SHARED CimExec.cpp)
set_property(TARGET CimExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
add_custom_command(TARGET CimExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
$<TARGET_FILE:CimExec> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:CimExec>")

if(WIN32)
    target_link_libraries(CimExec PRIVATE mi)
endif()

if(C2CORE_BUILD_TESTS)
    add_executable(testsCimExec tests/testsCimExec.cpp CimExec.cpp)
    target_link_libraries(testsCimExec PRIVATE c2_base64)
    if(WIN32)
        target_link_libraries(testsCimExec PRIVATE mi)
    endif()
    add_custom_command(TARGET testsCimExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsCimExec> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsCimExec>")

    add_test(NAME testsCimExec COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsCimExec>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_executable(testsCimExecFunctional tests/functional/testsCimExecFunctional.cpp CimExec.cpp)
    target_link_libraries(testsCimExecFunctional PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(testsCimExecFunctional PRIVATE C2CORE_BUILD_FUNCTIONAL_TESTS)
    target_include_directories(testsCimExecFunctional PRIVATE ../tests)
    if(WIN32)
        target_link_libraries(testsCimExecFunctional PRIVATE mi)
    endif()
    add_custom_command(TARGET testsCimExecFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsCimExecFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsCimExecFunctional>")

    add_test(NAME testsCimExecFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsCimExecFunctional>")
    set_tests_properties(testsCimExecFunctional PROPERTIES LABELS "functional;cim;windows-network" SKIP_RETURN_CODE 77)
endif()
