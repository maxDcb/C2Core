include_directories(../)
add_library(Upload SHARED Upload.cpp)
set_property(TARGET Upload PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Upload )
add_custom_command(TARGET Upload POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Upload> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Upload>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsUpload tests/testsUpload.cpp Upload.cpp)
    target_link_libraries(testsUpload )
    add_custom_command(TARGET testsUpload POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsUpload> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsUpload>")

    add_test(NAME testsUpload COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsUpload>")
endif()