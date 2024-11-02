include_directories(../)
add_library(Coff SHARED CoffLoader.cpp)
if(WIN32)
    target_link_libraries(Coff CoffLoader CoffPacker )
else()
endif()
add_custom_command(TARGET Coff POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Coff> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Coff>")

if(WITH_TESTS)
    add_executable(testsCoffLoader tests/testsCoffLoader.cpp CoffLoader.cpp)

    if(WIN32)
        target_link_libraries(testsCoffLoader CoffLoader CoffPacker )
    else()
    endif()

    add_custom_command(TARGET testsCoffLoader POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsCoffLoader> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsCoffLoader>")

    add_test(NAME testsCoffLoader COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsCoffLoader>")
endif()