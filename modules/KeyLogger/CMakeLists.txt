include_directories(../)
add_library(KeyLogger SHARED KeyLogger.cpp)
set_property(TARGET KeyLogger PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(KeyLogger )
add_custom_command(TARGET KeyLogger POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:KeyLogger> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:KeyLogger>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsKeyLogger tests/testsKeyLogger.cpp KeyLogger.cpp)
    target_compile_definitions(testsKeyLogger PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsKeyLogger )
    add_custom_command(TARGET testsKeyLogger POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsKeyLogger> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsKeyLogger>")

    add_test(NAME testsKeyLogger COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsKeyLogger>")
endif()
