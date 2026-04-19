include_directories(../)
add_library(WmiExec SHARED WmiExec.cpp)
set_property(TARGET WmiExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(WmiExec )
add_custom_command(TARGET WmiExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:WmiExec> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:WmiExec>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsWmiExec tests/testsWmiExec.cpp WmiExec.cpp)
    target_link_libraries(testsWmiExec )
    add_custom_command(TARGET testsWmiExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsWmiExec> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsWmiExec>")

    add_test(NAME testsWmiExec COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsWmiExec>")
endif()