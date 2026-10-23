include_directories(../)
if(WIN32)
    set(SYSCALL_OBJ "../ModuleCmd/syscall.x86.obj")
    if(CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
        set(SYSCALL_OBJ "../ModuleCmd/syscall.arm64.obj")
    elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(SYSCALL_OBJ "../ModuleCmd/syscall.x64.obj")
    endif()
    add_library(PwSh SHARED PwSh.cpp HostControl.cpp AssemblyManager.cpp AssemblyStore.cpp HostMalloc.cpp MemoryManager.cpp ../ModuleCmd/syscall.cpp ${SYSCALL_OBJ} )
else()
    add_library(PwSh SHARED PwSh.cpp)
endif()
set_property(TARGET PwSh PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(PwSh )
add_custom_command(TARGET PwSh POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
$<TARGET_FILE:PwSh> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:PwSh>")

if(DEFINED C2_RUNTIME_ROOT AND NOT "${C2_RUNTIME_ROOT}" STREQUAL "")
    add_custom_command(TARGET PwSh POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${C2_RUNTIME_ROOT}/data/Tools/Any/any"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/PowerShellRunner/rdm.dll"
            "${C2_RUNTIME_ROOT}/data/Tools/Any/any/rdm.dll")
endif()

if(C2CORE_BUILD_TESTS)
    if(WIN32)
        add_executable(testsPwSh tests/testsPwSh.cpp PwSh.cpp HostControl.cpp AssemblyManager.cpp AssemblyStore.cpp HostMalloc.cpp MemoryManager.cpp ../ModuleCmd/syscall.cpp ${SYSCALL_OBJ})
    else()
        add_executable(testsPwSh tests/testsPwSh.cpp PwSh.cpp)
    endif()
    # add_executable(testsPwSh WIN32 tests/testsPwSh.cpp PwSh.cpp HostControl.cpp AssemblyManager.cpp AssemblyStore.cpp HostMalloc.cpp MemoryManager.cpp ../ModuleCmd/syscall.cpp ../ModuleCmd/syscall.x64.obj)
    target_link_libraries(testsPwSh )
    set_property(TARGET testsPwSh PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    add_custom_command(TARGET testsPwSh POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsPwSh> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsPwSh>")

    add_test(NAME testsPwSh COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsPwSh>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    if(WIN32)
        add_executable(testsPwShFunctional tests/functional/testsPwShFunctional.cpp PwSh.cpp HostControl.cpp AssemblyManager.cpp AssemblyStore.cpp HostMalloc.cpp MemoryManager.cpp ../ModuleCmd/syscall.cpp ${SYSCALL_OBJ})
    else()
        add_executable(testsPwShFunctional tests/functional/testsPwShFunctional.cpp PwSh.cpp)
    endif()
    target_include_directories(testsPwShFunctional PRIVATE ../tests)
    target_link_libraries(testsPwShFunctional )
    set_property(TARGET testsPwShFunctional PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    add_custom_command(TARGET testsPwShFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsPwShFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsPwShFunctional>")

    add_test(NAME testsPwShFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsPwShFunctional>")
    set_tests_properties(testsPwShFunctional PROPERTIES LABELS "functional;pwsh;local-exec" SKIP_RETURN_CODE 77)
endif()
