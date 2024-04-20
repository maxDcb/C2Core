include_directories(../)
add_library(ListProcesses SHARED ListProcesses.cpp)
add_custom_command(TARGET ListProcesses POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:ListProcesses> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:ListProcesses>")

if(WITH_TESTS)
add_executable(testsListProcesses tests/testsListProcesses.cpp ListProcesses.cpp)
target_link_libraries(testsListProcesses)
add_custom_command(TARGET testsListProcesses POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsListProcesses> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsListProcesses>")

add_test(NAME testsListProcesses COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsListProcesses>")
endif()