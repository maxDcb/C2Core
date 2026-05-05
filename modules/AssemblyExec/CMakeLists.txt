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

c2core_disable_safeseh_for_x86(AssemblyExec)

add_custom_command(TARGET AssemblyExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:AssemblyExec> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:AssemblyExec>")

if(C2CORE_BUILD_TESTS OR C2CORE_BUILD_FUNCTIONAL_TESTS)
    if(WIN32)
        add_executable(assemblyExecDummyExe tests/dummyAssemblyExec.cpp)
    endif()
endif()

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
        add_executable(testOutputWriter tests/testOutputWriter.cpp)
    endif()

    add_custom_command(TARGET testsAssemblyExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsAssemblyExec> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsAssemblyExec>")

    if(WIN32)
        add_dependencies(testsAssemblyExec assemblyExecDummyExe)
        target_compile_definitions(testsAssemblyExec PRIVATE C2_ASSEMBLYEXEC_DUMMY_EXE="$<TARGET_FILE:assemblyExecDummyExe>")
    endif()

    add_custom_command(TARGET testOutputWriter POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testOutputWriter> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testOutputWriter>")

    add_test(NAME testsAssemblyExec COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsAssemblyExec>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    if(WIN32)
        if (CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
            add_executable(testsAssemblyExecFunctional
                tests/functional/testsAssemblyExecFunctional.cpp
                AssemblyExec.cpp
                ../ModuleCmd/syscall.cpp
                ${SYSCALL_OBJ}
                ../ModuleCmd/peb.cpp
                ../ModuleCmd/hwbp.cpp
            )
        elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
            add_executable(testsAssemblyExecFunctional
                tests/functional/testsAssemblyExecFunctional.cpp
                AssemblyExec.cpp
                ../ModuleCmd/syscall.cpp
                ${SYSCALL_OBJ}
                ../ModuleCmd/peb.cpp
                ../ModuleCmd/hwbp.cpp
            )
        else()
            add_executable(testsAssemblyExecFunctional
                tests/functional/testsAssemblyExecFunctional.cpp
                AssemblyExec.cpp
                ../ModuleCmd/syscall.cpp
                ${SYSCALL_OBJ}
                ../ModuleCmd/peb.cpp
                ../ModuleCmd/hwbp.cpp
            )
        endif()
        c2core_disable_safeseh_for_x86(testsAssemblyExecFunctional)
        target_link_libraries(testsAssemblyExecFunctional PRIVATE Donut)
        add_dependencies(testsAssemblyExecFunctional assemblyExecDummyExe)
        target_compile_definitions(testsAssemblyExecFunctional PRIVATE C2_ASSEMBLYEXEC_DUMMY_EXE="$<TARGET_FILE:assemblyExecDummyExe>")
    else()
        add_executable(testsAssemblyExecFunctional tests/functional/testsAssemblyExecFunctional.cpp AssemblyExec.cpp)
    endif()

    target_include_directories(testsAssemblyExecFunctional PRIVATE ../tests)
    add_custom_command(TARGET testsAssemblyExecFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsAssemblyExecFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsAssemblyExecFunctional>")

    add_test(NAME testsAssemblyExecFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsAssemblyExecFunctional>")
    set_tests_properties(testsAssemblyExecFunctional PROPERTIES LABELS "functional;assemblyexec;local-exec" SKIP_RETURN_CODE 77)
endif()
