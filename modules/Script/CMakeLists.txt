include_directories(../)
add_library(Script SHARED Script.cpp)
set_property(TARGET Script PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Script )
add_custom_command(TARGET Script POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Script> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Script>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsScript tests/testsScript.cpp Script.cpp)
    target_compile_definitions(testsScript PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsScript )
    add_custom_command(TARGET testsScript POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsScript> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsScript>")

    add_test(NAME testsScript COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsScript>")
endif()
