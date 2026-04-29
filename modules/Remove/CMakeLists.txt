include_directories(../)
add_library(Remove SHARED Remove.cpp)
set_property(TARGET Remove PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Remove )
add_custom_command(TARGET Remove POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:Remove> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Remove>"
)

if(C2CORE_BUILD_TESTS)
    add_executable(testsRemove tests/testsRemove.cpp Remove.cpp)
    target_compile_definitions(testsRemove PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsRemove )
    add_custom_command(TARGET testsRemove POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsRemove> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsRemove>")

    add_test(NAME testsRemove COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsRemove>")
endif()
