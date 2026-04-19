include_directories(../)
add_library(Download SHARED Download.cpp)
set_property(TARGET Download PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Download )
add_custom_command(TARGET Download POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Download> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Download>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsDownload tests/testsDownload.cpp Download.cpp)
    target_link_libraries(testsDownload )
    add_custom_command(TARGET testsDownload POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsDownload> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsDownload>")

    add_test(NAME testsDownload COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsDownload>")
endif()