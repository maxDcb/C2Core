
if(C2CORE_BUILD_TESTS)
    add_executable(testsModuleCmd tests/testsModuleCmd.cpp)
    target_compile_definitions(testsModuleCmd PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsModuleCmd nlohmann_json::nlohmann_json c2_base64)
    add_custom_command(TARGET testsModuleCmd POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsModuleCmd> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsModuleCmd>")
    add_test(NAME testsModuleCmd COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsModuleCmd>")

    add_executable(testsTools tests/testsTools.cpp)
    target_compile_definitions(testsTools PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsTools nlohmann_json::nlohmann_json c2_base64)
    add_custom_command(TARGET testsTools POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsTools> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTools>")
    add_test(NAME testsTools COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTools>")

    if(WIN32)
        set(SYSCALL_OBJ "./syscall.x86.obj")
        if(CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
            set(SYSCALL_OBJ "./syscall.arm64.obj")
        elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(SYSCALL_OBJ "./syscall.x64.obj")
        endif()

        add_executable(testsSyscall tests/testsSyscall.cpp ./syscall.cpp ${SYSCALL_OBJ})
        target_compile_definitions(testsSyscall PRIVATE C2CORE_BUILD_TESTS)
        target_link_libraries(testsSyscall )
        add_custom_command(TARGET testsSyscall POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
        $<TARGET_FILE:testsSyscall> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsSyscall>")
        add_test(NAME testsSyscall COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsSyscall>")

        add_executable(testsHwbp tests/testsHwbp.cpp ./hwbp.cpp ./peb.cpp)
        target_compile_definitions(testsHwbp PRIVATE C2CORE_BUILD_TESTS)
        target_link_libraries(testsHwbp )
        add_custom_command(TARGET testsHwbp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
        $<TARGET_FILE:testsHwbp> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsHwbp>")
        add_test(NAME testsHwbp COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsHwbp>")
    endif()
endif()
