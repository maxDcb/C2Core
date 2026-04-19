include_directories(../)
add_library(EnumerateShares SHARED EnumerateShares.cpp)
set_property(TARGET EnumerateShares PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
if(UNIX)
    target_link_libraries(EnumerateShares smbclient)
endif()
add_custom_command(TARGET EnumerateShares POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:EnumerateShares> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:EnumerateShares>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsEnumerateShares tests/testsEnumerateShares.cpp EnumerateShares.cpp)
    if(UNIX)
        target_link_libraries(testsEnumerateShares smbclient)
    endif()
    add_custom_command(TARGET testsEnumerateShares POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsEnumerateShares> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsEnumerateShares>")
    add_test(NAME testsEnumerateShares COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsEnumerateShares>")
endif()
