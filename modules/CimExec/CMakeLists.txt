include_directories(../)
add_library(CimExec SHARED CimExec.cpp)
set_property(TARGET CimExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
add_custom_command(TARGET CimExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
$<TARGET_FILE:CimExec> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:CimExec>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsCimExec tests/testsCimExec.cpp CimExec.cpp)
    add_custom_command(TARGET testsCimExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsCimExec> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsCimExec>")

    add_test(NAME testsCimExec COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsCimExec>")
endif()
