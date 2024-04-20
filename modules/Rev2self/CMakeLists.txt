include_directories(../)
add_library(Rev2self SHARED Rev2self.cpp)
add_custom_command(TARGET Rev2self POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Rev2self> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Rev2self>")

if(WITH_TESTS)
add_executable(testsRev2self tests/testsRev2self.cpp Rev2self.cpp)
target_link_libraries(testsRev2self)
add_custom_command(TARGET testsRev2self POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsRev2self> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsRev2self>")

add_test(NAME testsRev2self COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsRev2self>")
endif()