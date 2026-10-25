include_directories(../)
if(WIN32)
    set(SYSCALL_OBJ "../ModuleCmd/syscall.x86.obj")
    if(CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
        set(SYSCALL_OBJ "../ModuleCmd/syscall.arm64.obj")
    elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(SYSCALL_OBJ "../ModuleCmd/syscall.x64.obj")
    endif()
    add_library(DotnetExec SHARED DotnetExec.cpp HostControl.cpp AssemblyManager.cpp AssemblyStore.cpp HostMalloc.cpp MemoryManager.cpp ../ModuleCmd/syscall.cpp ${SYSCALL_OBJ} )
else()
    add_library(DotnetExec SHARED DotnetExec.cpp)
endif()
set_property(TARGET DotnetExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(DotnetExec )
add_custom_command(TARGET DotnetExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:DotnetExec> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:DotnetExec>")

if(C2CORE_BUILD_TESTS OR C2CORE_BUILD_FUNCTIONAL_TESTS)
    if(WIN32)
        find_program(C2_CSC_EXECUTABLE
            NAMES csc.exe
            HINTS
                "${CMAKE_GENERATOR_INSTANCE}/MSBuild/Current/Bin/Roslyn"
                "$ENV{VSINSTALLDIR}/MSBuild/Current/Bin/Roslyn"
                "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/Enterprise/MSBuild/Current/Bin/Roslyn"
                "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/Professional/MSBuild/Current/Bin/Roslyn"
                "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/Community/MSBuild/Current/Bin/Roslyn"
                "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/BuildTools/MSBuild/Current/Bin/Roslyn")

        if(C2CORE_BUILD_TESTS AND NOT C2_CSC_EXECUTABLE)
            message(FATAL_ERROR "DotnetExec tests require csc.exe from the selected Visual Studio instance")
        endif()

        if(C2_CSC_EXECUTABLE)
            set(C2_DOTNETEXEC_DUMMY_EXE "${CMAKE_CURRENT_BINARY_DIR}/DummyDotnetExec.exe")
            add_custom_command(
                OUTPUT "${C2_DOTNETEXEC_DUMMY_EXE}"
                COMMAND "${C2_CSC_EXECUTABLE}" /nologo /target:exe /platform:anycpu "/out:${C2_DOTNETEXEC_DUMMY_EXE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/DummyDotnetExec.cs"
                DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/DummyDotnetExec.cs"
                VERBATIM)
            add_custom_target(dummyDotnetExecAssembly DEPENDS "${C2_DOTNETEXEC_DUMMY_EXE}")
        endif()
    endif()
endif()

if(C2CORE_BUILD_TESTS)
    if(WIN32)
        add_executable(testsDotnetExec tests/testsDotnetExec.cpp DotnetExec.cpp HostControl.cpp AssemblyManager.cpp AssemblyStore.cpp HostMalloc.cpp MemoryManager.cpp ../ModuleCmd/syscall.cpp ${SYSCALL_OBJ} tests/project.rc)
        if(C2_CSC_EXECUTABLE)
            add_dependencies(testsDotnetExec dummyDotnetExecAssembly)
            target_compile_definitions(testsDotnetExec PRIVATE C2_DOTNETEXEC_DUMMY_EXE="${C2_DOTNETEXEC_DUMMY_EXE}")
        endif()
    else()
        add_executable(testsDotnetExec tests/testsDotnetExec.cpp DotnetExec.cpp)
    endif()
    # add_executable(testsDotnetExec WIN32 tests/testsDotnetExec.cpp DotnetExec.cpp HostControl.cpp AssemblyManager.cpp AssemblyStore.cpp HostMalloc.cpp MemoryManager.cpp ../ModuleCmd/syscall.cpp ../ModuleCmd/syscall.x64.obj tests/project.rc)
    target_link_libraries(testsDotnetExec )
    set_property(TARGET testsDotnetExec PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    add_custom_command(TARGET testsDotnetExec POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsDotnetExec> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsDotnetExec>")

    add_test(NAME testsDotnetExec COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsDotnetExec>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    if(WIN32)
        add_executable(testsDotnetExecFunctional tests/functional/testsDotnetExecFunctional.cpp DotnetExec.cpp HostControl.cpp AssemblyManager.cpp AssemblyStore.cpp HostMalloc.cpp MemoryManager.cpp ../ModuleCmd/syscall.cpp ${SYSCALL_OBJ})
        if(C2_CSC_EXECUTABLE)
            add_dependencies(testsDotnetExecFunctional dummyDotnetExecAssembly)
            target_compile_definitions(testsDotnetExecFunctional PRIVATE C2_DOTNETEXEC_DUMMY_EXE="${C2_DOTNETEXEC_DUMMY_EXE}")
        endif()
    else()
        add_executable(testsDotnetExecFunctional tests/functional/testsDotnetExecFunctional.cpp DotnetExec.cpp)
    endif()
    target_include_directories(testsDotnetExecFunctional PRIVATE ../tests)
    target_link_libraries(testsDotnetExecFunctional )
    set_property(TARGET testsDotnetExecFunctional PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    add_custom_command(TARGET testsDotnetExecFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsDotnetExecFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsDotnetExecFunctional>")

    add_test(NAME testsDotnetExecFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsDotnetExecFunctional>")
    set_tests_properties(testsDotnetExecFunctional PROPERTIES LABELS "functional;dotnetexec;local-exec" SKIP_RETURN_CODE 77)
endif()
