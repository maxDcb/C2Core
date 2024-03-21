include_directories(../)
add_library(Powershell SHARED Powershell.cpp)
add_custom_command(TARGET Powershell POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Powershell> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Powershell>")

add_executable(testsPowershell tests/testsPowershell.cpp Powershell.cpp)
target_link_libraries(testsPowershell)
add_custom_command(TARGET testsPowershell POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:testsPowershell> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsPowershell>")

add_test(NAME testsPowershell COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsPowershell>")