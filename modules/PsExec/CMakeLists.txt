include_directories(../)
add_library(PsExec SHARED PsExec.cpp)
set_property(TARGET PsExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(PsExec )
add_custom_command(TARGET PsExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:PsExec> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:PsExec>")

if(C2CORE_BUILD_TESTS)
    # PsExec test
    add_executable(testsPsExec tests/testsPsExec.cpp PsExec.cpp)
    target_link_libraries(testsPsExec )
    add_custom_command(TARGET testsPsExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsPsExec> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsPsExec>")

    add_test(NAME testsPsExec COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsPsExec>")

    if (WIN32)

        # TestService 
        add_executable(TestService tests/TestService.cpp)
        target_link_libraries(TestService PRIVATE
            advapi32
        )
        add_custom_command(TARGET TestService POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy
                $<TARGET_FILE:TestService>
                "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:TestService>"
        )

    endif (WIN32)

endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_executable(testsPsExecFunctional tests/functional/testsPsExecFunctional.cpp PsExec.cpp)
    target_include_directories(testsPsExecFunctional PRIVATE ../tests)
    target_compile_definitions(testsPsExecFunctional PRIVATE C2CORE_BUILD_FUNCTIONAL_TESTS)
    target_link_libraries(testsPsExecFunctional c2_base64 nlohmann_json::nlohmann_json)

    add_custom_command(TARGET testsPsExecFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsPsExecFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsPsExecFunctional>")

    if (WIN32)
        if (NOT TARGET TestService)
            add_executable(TestService tests/TestService.cpp)
            target_link_libraries(TestService PRIVATE advapi32)
            add_custom_command(TARGET TestService POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                    $<TARGET_FILE:TestService>
                    "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:TestService>"
            )
        endif()
        add_dependencies(testsPsExecFunctional TestService)
        target_compile_definitions(testsPsExecFunctional PRIVATE C2_PSEXEC_TEST_SERVICE="$<TARGET_FILE:TestService>")
    endif()

    add_test(NAME testsPsExecFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsPsExecFunctional>")
    set_tests_properties(testsPsExecFunctional PROPERTIES LABELS "functional;psexec;windows-network" SKIP_RETURN_CODE 77)
endif()
