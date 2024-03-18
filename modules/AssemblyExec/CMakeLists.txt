include_directories(../)
add_library(AssemblyExec SHARED ../ModuleCmd/ModuleCmd.cpp AssemblyExec.cpp)
target_link_libraries(AssemblyExec ${Donut})
add_custom_command(TARGET AssemblyExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:AssemblyExec> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:AssemblyExec>")

add_executable(testsAssemblyExec tests/testsAssemblyExec.cpp ../ModuleCmd/ModuleCmd.cpp AssemblyExec.cpp)

if(WIN32)
    target_link_libraries(testsAssemblyExec ${Donut} )
else()
    target_link_libraries(testsAssemblyExec ${Donut} ${aplib64} )
endif()

add_custom_command(TARGET testsAssemblyExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsAssemblyExec> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsAssemblyExec>")

add_test(NAME testsAssemblyExec COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsAssemblyExec>")