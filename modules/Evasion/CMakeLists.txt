include_directories(../)
add_library(Evasion SHARED Evasion.cpp)
set_property(TARGET Evasion PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Evasion )
add_custom_command(TARGET Evasion POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Evasion> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Evasion>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsEvasion tests/testsEvasion.cpp Evasion.cpp)
    target_link_libraries(testsEvasion )
    add_custom_command(TARGET testsEvasion POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsEvasion> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsEvasion>")

    add_test(NAME testsEvasion COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsEvasion>")
endif()
