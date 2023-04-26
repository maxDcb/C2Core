include_directories(../)
add_library(Inject SHARED ../ModuleCmd/ModuleCmd.cpp Inject.cpp)
target_link_libraries(Inject ${Donut})
add_custom_command(TARGET Inject POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Inject> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Inject>")

add_executable(testsInject tests/testsInject.cpp ../ModuleCmd/ModuleCmd.cpp Inject.cpp)
target_link_libraries(testsInject ${Donut})
add_custom_command(TARGET testsInject POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsInject> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsInject>")