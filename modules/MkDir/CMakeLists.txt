include_directories(../)
add_library(MkDir SHARED MkDir.cpp)
set_property(TARGET MkDir PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(MkDir )
add_custom_command(TARGET MkDir POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:MkDir> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:MkDir>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsMkDir tests/testsMkDir.cpp MkDir.cpp)
    target_link_libraries(testsMkDir )
    add_custom_command(TARGET testsMkDir POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsMkDir> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsMkDir>")
    add_test(NAME testsMkDir COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsMkDir>")
endif()
