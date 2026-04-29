include_directories(../)
add_library(Tree SHARED Tree.cpp)
set_property(TARGET Tree PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Tree )
add_custom_command(TARGET Tree POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Tree> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Tree>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsTree tests/testsTree.cpp Tree.cpp)
    target_compile_definitions(testsTree PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsTree )
    add_custom_command(TARGET testsTree POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsTree> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTree>")

    add_test(NAME testsTree COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsTree>")
endif()
