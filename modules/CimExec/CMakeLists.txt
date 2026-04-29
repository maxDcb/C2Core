include_directories(../)
add_library(CimExec SHARED CimExec.cpp)
set_property(TARGET CimExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
add_custom_command(TARGET CimExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
$<TARGET_FILE:CimExec> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:CimExec>")

if(WIN32)
    target_link_libraries(CimExec PRIVATE mi)
endif()

if(C2CORE_BUILD_TESTS)
    add_executable(testsCimExec tests/testsCimExec.cpp CimExec.cpp)
    target_compile_definitions(testsCimExec PRIVATE C2CORE_BUILD_TESTS)
    if(WIN32)
        target_link_libraries(testsCimExec PRIVATE mi)
    endif()
    add_custom_command(TARGET testsCimExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsCimExec> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsCimExec>")

    add_test(NAME testsCimExec COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsCimExec>")
endif()
