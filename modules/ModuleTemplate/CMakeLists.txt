include_directories(../)
add_library(ModuleTemplate SHARED ModuleTemplate.cpp)
set_property(TARGET ModuleTemplate PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(ModuleTemplate )
add_custom_command(TARGET ModuleTemplate POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:ModuleTemplate> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:ModuleTemplate>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsModuleTemplate tests/testsModuleTemplate.cpp ModuleTemplate.cpp)
    target_compile_definitions(testsModuleTemplate PRIVATE C2CORE_BUILD_TESTS)
    target_link_libraries(testsModuleTemplate )
    add_custom_command(TARGET testsModuleTemplate POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsModuleTemplate> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsModuleTemplate>")

    add_test(NAME testsModuleTemplate COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsModuleTemplate>")
endif()
