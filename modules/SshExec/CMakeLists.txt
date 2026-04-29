include_directories(../)
add_library(SshExec SHARED SshExec.cpp)
set_property(TARGET SshExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

# Link against Conan-provided static libssh2 and its transitive dependencies.
target_link_libraries(SshExec PRIVATE Libssh2::libssh2)

# Windows-specific dependencies
if (WIN32)
    target_link_libraries(SshExec PRIVATE 
        ws2_32
        crypt32
        bcrypt
    )
endif()


add_custom_command(TARGET SshExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:SshExec> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:SshExec>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsSshExec tests/testsSshExec.cpp SshExec.cpp)
    target_link_libraries(testsSshExec PRIVATE Libssh2::libssh2)
    target_compile_definitions(testsSshExec PRIVATE C2CORE_BUILD_TESTS)
    if (WIN32)
        target_link_libraries(testsSshExec PRIVATE 
            ws2_32
            crypt32
            bcrypt
        )
    endif()
    add_custom_command(TARGET testsSshExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsSshExec> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsSshExec>")
    add_test(NAME testsSshExec COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsSshExec>")
endif()
