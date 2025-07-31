include_directories(../)
add_library(SmbExec SHARED SmbExec.cpp)
set_property(TARGET SmbExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(SmbExec )
add_custom_command(TARGET SmbExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:SmbExec> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:SmbExec>")

if(WITH_TESTS)
    add_executable(testsSmbExec tests/testsSmbExec.cpp SmbExec.cpp)
    target_link_libraries(testsSmbExec )
    add_custom_command(TARGET testsSmbExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsSmbExec> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsSmbExec>")
    add_test(NAME testsSmbExec COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsSmbExec>")
endif()
