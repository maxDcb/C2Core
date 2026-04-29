include_directories(../)

if(WIN32)
    set(SYSCALL_OBJ "../ModuleCmd/syscall.x86.obj")
    if(CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
        set(SYSCALL_OBJ "../ModuleCmd/syscall.arm64.obj")
    elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(SYSCALL_OBJ "../ModuleCmd/syscall.x64.obj")
    endif()

    if (CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
        add_library(MiniDump SHARED
            MiniDump.cpp
            ../ModuleCmd/syscall.cpp
            ${SYSCALL_OBJ}
        )
    elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)   # x64
        add_library(MiniDump SHARED
            MiniDump.cpp
            ../ModuleCmd/syscall.cpp
            ${SYSCALL_OBJ}
        )
    else()                             # 32-bit
        add_library(MiniDump SHARED
            MiniDump.cpp
            ../ModuleCmd/syscall.cpp
            ${SYSCALL_OBJ}
        )
    endif()
else()
    add_library(MiniDump SHARED MiniDump.cpp)
endif()

set_property(TARGET MiniDump PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(MiniDump ${Donut})
c2core_disable_safeseh_for_x86(MiniDump)


add_custom_command(TARGET MiniDump POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:MiniDump> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:MiniDump>")


if(C2CORE_BUILD_TESTS)
    if(WIN32)
        if (CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
            add_executable(testsMiniDump
                tests/testsMiniDump.cpp
                MiniDump.cpp
                ../ModuleCmd/syscall.cpp
                ${SYSCALL_OBJ}
            )
        elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)   # x64
            add_executable(testsMiniDump
                tests/testsMiniDump.cpp
                MiniDump.cpp
                ../ModuleCmd/syscall.cpp
                ${SYSCALL_OBJ}
            )
        else()                             # 32-bit
            add_executable(testsMiniDump
                tests/testsMiniDump.cpp
                MiniDump.cpp
                ../ModuleCmd/syscall.cpp
                ${SYSCALL_OBJ}
            )
        endif()
    else()
    add_executable(testsMiniDump tests/testsMiniDump.cpp MiniDump.cpp)
    endif()
    set_property(TARGET testsMiniDump PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_libraries(testsMiniDump ${Donut})
    c2core_disable_safeseh_for_x86(testsMiniDump)

    add_custom_command(TARGET testsMiniDump POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsMiniDump> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsMiniDump>")

    add_test(NAME testsMiniDump COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsMiniDump>")
endif()
