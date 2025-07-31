include_directories(../)
add_library(GetEnv SHARED GetEnv.cpp)
set_property(TARGET GetEnv PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(GetEnv )
add_custom_command(TARGET GetEnv POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:GetEnv> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:GetEnv>")

if(WITH_TESTS)
    add_executable(testsGetEnv tests/testsGetEnv.cpp GetEnv.cpp)
    target_link_libraries(testsGetEnv )
    add_custom_command(TARGET testsGetEnv POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsGetEnv> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsGetEnv>")
    add_test(NAME testsGetEnv COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsGetEnv>")
endif()
