include_directories(../)
add_library(Rev2self SHARED Rev2self.cpp)
set_property(TARGET Rev2self PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Rev2self )
add_custom_command(TARGET Rev2self POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Rev2self> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Rev2self>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsRev2self tests/testsRev2self.cpp Rev2self.cpp)
    target_compile_definitions(testsRev2self PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsRev2self )
    add_custom_command(TARGET testsRev2self POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsRev2self> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsRev2self>")

    add_test(NAME testsRev2self COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsRev2self>")
endif()
