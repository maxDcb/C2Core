include_directories(../)
add_library(Cat SHARED Cat.cpp)
set_property(TARGET Cat PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Cat )
add_custom_command(TARGET Cat POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Cat> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Cat>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsCat tests/testsCat.cpp Cat.cpp)
    target_compile_definitions(testsCat PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsCat )
    add_custom_command(TARGET testsCat POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsCat> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsCat>")

    add_test(NAME testsCat COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsCat>")
endif()
