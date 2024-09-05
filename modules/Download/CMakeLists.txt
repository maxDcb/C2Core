include_directories(../)
add_library(Download SHARED Download.cpp)
target_link_libraries(Download )
add_custom_command(TARGET Download POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Download> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Download>")

if(WITH_TESTS)
    add_executable(testsDownload tests/testsDownload.cpp Download.cpp)
    target_link_libraries(testsDownload )
    add_custom_command(TARGET testsDownload POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsDownload> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsDownload>")

    add_test(NAME testsDownload COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsDownload>")
endif()