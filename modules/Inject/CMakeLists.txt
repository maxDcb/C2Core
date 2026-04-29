include_directories(../)

if(WIN32)
    set(SYSCALL_OBJ "../ModuleCmd/syscall.x86.obj")
    if(CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
        set(SYSCALL_OBJ "../ModuleCmd/syscall.arm64.obj")
    elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(SYSCALL_OBJ "../ModuleCmd/syscall.x64.obj")
    endif()

    add_library(Inject SHARED
        Inject.cpp
        ../ModuleCmd/syscall.cpp
        ${SYSCALL_OBJ}
    )
else()
    add_library(Inject SHARED Inject.cpp)
endif()

set_property(TARGET Inject PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

if(C2CORE_BUILD_TESTS)
    target_link_libraries(Inject PRIVATE Donut )
endif()
c2core_disable_safeseh_for_x86(Inject)

add_custom_command(TARGET Inject POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Inject> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Inject>")

if(C2CORE_BUILD_TESTS)
    if(WIN32)
       add_executable(testsInject tests/testsInject.cpp Inject.cpp ../ModuleCmd/syscall.cpp ${SYSCALL_OBJ})
        target_link_libraries(testsInject PRIVATE Donut )
        c2core_disable_safeseh_for_x86(testsInject)
    else()
        add_executable(testsInject tests/testsInject.cpp Inject.cpp)
        target_link_libraries(testsInject PRIVATE Donut ${aplib64} )
    endif()

    add_custom_command(TARGET testsInject POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsInject> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsInject>")

    add_test(NAME testsInject COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsInject>")
endif()
