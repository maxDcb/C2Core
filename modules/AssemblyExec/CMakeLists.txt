include_directories(../)

if(WIN32)
    set(SYSCALL_OBJ "../ModuleCmd/syscall.x86.obj")
    if(CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
        set(SYSCALL_OBJ "../ModuleCmd/syscall.arm64.obj")
    elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(SYSCALL_OBJ "../ModuleCmd/syscall.x64.obj")
    endif()

    if (CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
        add_library(AssemblyExec SHARED
            AssemblyExec.cpp
            ../ModuleCmd/syscall.cpp
            ${SYSCALL_OBJ}
            ../ModuleCmd/peb.cpp
            ../ModuleCmd/hwbp.cpp
        )
    elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)   # x64
        add_library(AssemblyExec SHARED
            AssemblyExec.cpp
            ../ModuleCmd/syscall.cpp
            ${SYSCALL_OBJ}
            ../ModuleCmd/peb.cpp
            ../ModuleCmd/hwbp.cpp
        )
    else()                             # 32-bit (x86)
        add_library(AssemblyExec SHARED
            AssemblyExec.cpp
            ../ModuleCmd/syscall.cpp
            ${SYSCALL_OBJ}
            ../ModuleCmd/peb.cpp
            ../ModuleCmd/hwbp.cpp
        )
    endif()
else()
    add_library(AssemblyExec SHARED AssemblyExec.cpp)
endif()

set_property(TARGET AssemblyExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

if(C2CORE_BUILD_TESTS)
    target_link_libraries(AssemblyExec PRIVATE Donut )
endif()
c2core_disable_safeseh_for_x86(AssemblyExec)

add_custom_command(TARGET AssemblyExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:AssemblyExec> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:AssemblyExec>")

if(C2CORE_BUILD_TESTS)
    if(WIN32)
        if (CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
            add_executable(testsAssemblyExec
                tests/testsAssemblyExec.cpp
                AssemblyExec.cpp
                ../ModuleCmd/syscall.cpp
                ${SYSCALL_OBJ}
                ../ModuleCmd/peb.cpp
                ../ModuleCmd/hwbp.cpp
            )
        elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)   # x64
            add_executable(testsAssemblyExec
                tests/testsAssemblyExec.cpp
                AssemblyExec.cpp
                ../ModuleCmd/syscall.cpp
                ${SYSCALL_OBJ}
                ../ModuleCmd/peb.cpp
                ../ModuleCmd/hwbp.cpp
            )
        else()                             # 32-bit
            add_executable(testsAssemblyExec
                tests/testsAssemblyExec.cpp
                AssemblyExec.cpp
                ../ModuleCmd/syscall.cpp
                ${SYSCALL_OBJ}
                ../ModuleCmd/peb.cpp
                ../ModuleCmd/hwbp.cpp
            )
        endif()
        target_link_libraries(testsAssemblyExec PRIVATE Donut )
        c2core_disable_safeseh_for_x86(testsAssemblyExec)

        add_executable(testOutputWriter tests/testOutputWriter.cpp)
    else()
        add_executable(testsAssemblyExec tests/testsAssemblyExec.cpp AssemblyExec.cpp)
        target_link_libraries(testsAssemblyExec PRIVATE Donut ${aplib64} )

        add_executable(testOutputWriter tests/testOutputWriter.cpp)
    endif()

    add_custom_command(TARGET testsAssemblyExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsAssemblyExec> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsAssemblyExec>")

    add_custom_command(TARGET testOutputWriter POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testOutputWriter> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testOutputWriter>")

    add_test(NAME testsAssemblyExec COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsAssemblyExec>")
endif()
