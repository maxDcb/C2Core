include_directories(../)
add_library(Evasion SHARED Evasion.cpp)
set_property(TARGET Evasion PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Evasion )
add_custom_command(TARGET Evasion POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Evasion> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Evasion>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsEvasion tests/testsEvasion.cpp Evasion.cpp)
    target_compile_definitions(testsEvasion PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsEvasion )
    add_custom_command(TARGET testsEvasion POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsEvasion> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsEvasion>")

    add_test(NAME testsEvasion COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsEvasion>")
endif()
