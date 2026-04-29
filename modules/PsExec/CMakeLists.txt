include_directories(../)
add_library(PsExec SHARED PsExec.cpp)
set_property(TARGET PsExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(PsExec )
add_custom_command(TARGET PsExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:PsExec> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:PsExec>")

if(C2CORE_BUILD_TESTS)
    # PsExec test
    add_executable(testsPsExec tests/testsPsExec.cpp PsExec.cpp)
    target_compile_definitions(testsPsExec PRIVATE C2CORE_BUILD_TESTS)
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
