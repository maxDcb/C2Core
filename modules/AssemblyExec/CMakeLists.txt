include_directories(../)

if(WIN32)
    add_library(AssemblyExec SHARED AssemblyExec.cpp ../ModuleCmd/syscall.cpp ../ModuleCmd/syscall.x64.obj ../ModuleCmd/peb.cpp ../ModuleCmd/hwbp.cpp)
else()
    add_library(AssemblyExec SHARED AssemblyExec.cpp)
endif()

set_property(TARGET AssemblyExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

if(C2CORE_BUILD_TESTS)
    message(STATUS "[+] AssemblyExec Tests are enable.")
    target_link_libraries(AssemblyExec PRIVATE Donut)
else()
    message(STATUS "[-] AssemblyExec Tests are disable.")    
    target_link_libraries(AssemblyExec PRIVATE Donut)
endif()

add_custom_command(TARGET AssemblyExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:AssemblyExec> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:AssemblyExec>")

if(C2CORE_BUILD_TESTS)
    if(WIN32)
        add_executable(testsAssemblyExec tests/testsAssemblyExec.cpp AssemblyExec.cpp ../ModuleCmd/syscall.cpp ../ModuleCmd/syscall.x64.obj ../ModuleCmd/peb.cpp ../ModuleCmd/hwbp.cpp)
        target_link_libraries(testsAssemblyExec PRIVATE Donut )

        add_executable(testOutputWriter tests/testOutputWriter.cpp)
    else()
        add_executable(testsAssemblyExec tests/testsAssemblyExec.cpp AssemblyExec.cpp)
        target_link_libraries(testsAssemblyExec PRIVATE Donut ${aplib64} )

        add_executable(testOutputWriter tests/testOutputWriter.cpp)
    endif()

    add_custom_command(TARGET testsAssemblyExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsAssemblyExec> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsAssemblyExec>")

    add_custom_command(TARGET testOutputWriter POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testOutputWriter> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testOutputWriter>")

    add_test(NAME testsAssemblyExec COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsAssemblyExec>")
endif()
