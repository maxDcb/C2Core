include_directories(../)
add_library(Remove SHARED Remove.cpp)
set_property(TARGET Remove PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Remove )
add_custom_command(TARGET Remove POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:Remove> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Remove>"
)

if(WITH_TESTS)
    add_executable(testsRemove tests/testsRemove.cpp Remove.cpp)
    target_link_libraries(testsRemove )
    add_custom_command(TARGET testsRemove POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsRemove> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsRemove>")

    add_test(NAME testsRemove COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsRemove>")
endif()
