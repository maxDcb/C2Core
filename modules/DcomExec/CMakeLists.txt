include_directories(../)
add_library(DcomExec SHARED DcomExec.cpp)
set_property(TARGET DcomExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
if (WIN32)
    target_compile_definitions(DcomExec PRIVATE _WIN32_WINNT=0x0601)
    target_link_libraries(DcomExec PRIVATE ole32 oleaut32)
endif()
add_custom_command(TARGET DcomExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
$<TARGET_FILE:DcomExec> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:DcomExec>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsDcomExec tests/testsDcomExec.cpp DcomExec.cpp)
    if (WIN32)
        target_compile_definitions(testsDcomExec PRIVATE _WIN32_WINNT=0x0601)
        target_link_libraries(testsDcomExec PRIVATE ole32 oleaut32)
    endif()
    add_custom_command(TARGET testsDcomExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsDcomExec> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsDcomExec>")

    add_test(NAME testsDcomExec COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsDcomExec>")
endif()
