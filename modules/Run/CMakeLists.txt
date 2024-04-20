include_directories(../)
add_library(Run SHARED Run.cpp)
add_custom_command(TARGET Run POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Run> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Run>")

if(WITH_TESTS)
add_executable(testsRun tests/testsRun.cpp Run.cpp)
target_link_libraries(testsRun)
add_custom_command(TARGET testsRun POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsRun> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsRun>")

add_test(NAME testsRun COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsRun>")
endif()