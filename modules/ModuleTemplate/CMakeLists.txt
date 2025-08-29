include_directories(../)
add_library(ModuleTemplate SHARED ModuleTemplate.cpp)
set_property(TARGET ModuleTemplate PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(ModuleTemplate )
add_custom_command(TARGET ModuleTemplate POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:ModuleTemplate> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:ModuleTemplate>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsModuleTemplate tests/testsModuleTemplate.cpp ModuleTemplate.cpp)
    target_link_libraries(testsModuleTemplate )
    add_custom_command(TARGET testsModuleTemplate POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsModuleTemplate> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsModuleTemplate>")

    add_test(NAME testsModuleTemplate COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsModuleTemplate>")
endif()