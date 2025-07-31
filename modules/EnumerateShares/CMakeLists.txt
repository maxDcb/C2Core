include_directories(../)
add_library(EnumerateShares SHARED EnumerateShares.cpp)
set_property(TARGET EnumerateShares PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
if(UNIX)
    target_link_libraries(EnumerateShares smbclient)
endif()
add_custom_command(TARGET EnumerateShares POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:EnumerateShares> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:EnumerateShares>")

if(WITH_TESTS)
    add_executable(testsEnumerateShares tests/testsEnumerateShares.cpp EnumerateShares.cpp)
    if(UNIX)
        target_link_libraries(testsEnumerateShares smbclient)
    endif()
    add_custom_command(TARGET testsEnumerateShares POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsEnumerateShares> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsEnumerateShares>")
    add_test(NAME testsEnumerateShares COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsEnumerateShares>")
endif()
