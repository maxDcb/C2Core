include_directories(../)
add_library(Whoami SHARED Whoami.cpp)
set_property(TARGET Whoami PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Whoami )
add_custom_command(TARGET Whoami POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:Whoami> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Whoami>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsWhoami tests/testsWhoami.cpp Whoami.cpp)
    target_link_libraries(testsWhoami )
    add_custom_command(TARGET testsWhoami POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsWhoami> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsWhoami>")
    add_test(NAME testsWhoami COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsWhoami>")
endif()
