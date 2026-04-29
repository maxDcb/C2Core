include_directories(../)
add_library(MakeToken SHARED MakeToken.cpp)
set_property(TARGET MakeToken PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(MakeToken )
add_custom_command(TARGET MakeToken POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:MakeToken> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:MakeToken>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsMakeToken tests/testsMakeToken.cpp MakeToken.cpp)
    target_compile_definitions(testsMakeToken PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsMakeToken )
    add_custom_command(TARGET testsMakeToken POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsMakeToken> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsMakeToken>")

    add_test(NAME testsMakeToken COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsMakeToken>")
endif()
