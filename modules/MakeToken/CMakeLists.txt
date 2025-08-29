include_directories(../)
add_library(MakeToken SHARED MakeToken.cpp)
set_property(TARGET MakeToken PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(MakeToken )
add_custom_command(TARGET MakeToken POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:MakeToken> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:MakeToken>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsMakeToken tests/testsMakeToken.cpp MakeToken.cpp)
    target_link_libraries(testsMakeToken )
    add_custom_command(TARGET testsMakeToken POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsMakeToken> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsMakeToken>")

    add_test(NAME testsMakeToken COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsMakeToken>")
endif()