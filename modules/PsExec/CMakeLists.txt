include_directories(../)
add_library(PsExec SHARED PsExec.cpp)
set_property(TARGET PsExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(PsExec )
add_custom_command(TARGET PsExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:PsExec> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:PsExec>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsPsExec tests/testsPsExec.cpp PsExec.cpp)
    target_link_libraries(testsPsExec )
    add_custom_command(TARGET testsPsExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsPsExec> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsPsExec>")

    add_test(NAME testsPsExec COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsPsExec>")
endif()