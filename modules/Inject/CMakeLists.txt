include_directories(../)

if(WIN32)
    add_library(Inject SHARED Inject.cpp ../ModuleCmd/syscall.cpp ../ModuleCmd/syscall.x64.obj)
else()
    add_library(Inject SHARED Inject.cpp)
endif()

set_property(TARGET Inject PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

target_link_libraries(Inject PRIVATE Donut )

add_custom_command(TARGET Inject POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Inject> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Inject>")

if(C2CORE_BUILD_TESTS)
    if(WIN32)
       add_executable(testsInject tests/testsInject.cpp Inject.cpp ../ModuleCmd/syscall.cpp ../ModuleCmd/syscall.x64.obj)
        target_link_libraries(testsInject PRIVATE Donut )
    else()
        add_executable(testsInject tests/testsInject.cpp Inject.cpp)
        target_link_libraries(testsInject PRIVATE Donut ${aplib64} )
    endif()

    add_custom_command(TARGET testsInject POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsInject> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsInject>")

    add_test(NAME testsInject COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsInject>")
endif()
