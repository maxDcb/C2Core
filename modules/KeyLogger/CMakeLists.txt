include_directories(../)
add_library(KeyLogger SHARED KeyLogger.cpp)
set_property(TARGET KeyLogger PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(KeyLogger )
add_custom_command(TARGET KeyLogger POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:KeyLogger> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:KeyLogger>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsKeyLogger tests/testsKeyLogger.cpp KeyLogger.cpp)
    target_link_libraries(testsKeyLogger )
    add_custom_command(TARGET testsKeyLogger POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsKeyLogger> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsKeyLogger>")

    add_test(NAME testsKeyLogger COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsKeyLogger>")
endif()