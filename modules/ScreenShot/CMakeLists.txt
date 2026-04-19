include_directories(../)
add_library(ScreenShot SHARED ScreenShot.cpp ScreenShooter.cpp)
set_property(TARGET ScreenShot PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(ScreenShot )
add_custom_command(TARGET ScreenShot POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:ScreenShot> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:ScreenShot>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsScreenShot tests/testsScreenShot.cpp ScreenShot.cpp ScreenShooter.cpp)
    target_link_libraries(testsScreenShot )
    add_custom_command(TARGET testsScreenShot POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsScreenShot> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsScreenShot>")

    add_test(NAME testsScreenShot COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsScreenShot>")
endif()