include_directories(../)
add_library(Tree SHARED Tree.cpp)
set_property(TARGET Tree PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Tree )
add_custom_command(TARGET Tree POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Tree> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Tree>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsTree tests/testsTree.cpp Tree.cpp)
    target_link_libraries(testsTree )
    add_custom_command(TARGET testsTree POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsTree> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsTree>")

    add_test(NAME testsTree COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsTree>")
endif()