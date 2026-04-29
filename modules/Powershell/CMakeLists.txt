include_directories(../)
add_library(Powershell SHARED Powershell.cpp)
set_property(TARGET Powershell PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Powershell )
add_custom_command(TARGET Powershell POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Powershell> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Powershell>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsPowershell tests/testsPowershell.cpp Powershell.cpp)
    target_link_libraries(testsPowershell )
    add_custom_command(TARGET testsPowershell POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsPowershell> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsPowershell>")

    add_test(NAME testsPowershell COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsPowershell>")
endif()
