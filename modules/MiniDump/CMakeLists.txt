include_directories(../)

if(WIN32)
    add_library(MiniDump SHARED MiniDump.cpp ../ModuleCmd/syscall.cpp ../ModuleCmd/syscall.x64.obj)
else()
    add_library(MiniDump SHARED MiniDump.cpp)
endif()

set_property(TARGET MiniDump PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(MiniDump ${Donut})


add_custom_command(TARGET MiniDump POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:MiniDump> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:MiniDump>")


if(WITH_TESTS)
    if(WIN32)
        add_executable(testsMiniDump tests/testsMiniDump.cpp MiniDump.cpp ../ModuleCmd/syscall.cpp ../ModuleCmd/syscall.x64.obj)
    else()
    add_executable(testsMiniDump tests/testsMiniDump.cpp MiniDump.cpp)
    endif()
    set_property(TARGET testsMiniDump PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_libraries(testsMiniDump ${Donut})

    add_custom_command(TARGET testsMiniDump POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsMiniDump> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsMiniDump>")

    add_test(NAME testsMiniDump COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsMiniDump>")
endif()