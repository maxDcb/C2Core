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

if((C2CORE_BUILD_TESTS OR C2CORE_BUILD_FUNCTIONAL_TESTS) AND NOT WIN32)
    target_link_libraries(Inject PRIVATE Donut )
endif()
c2core_disable_safeseh_for_x86(Inject)

add_custom_command(TARGET Inject POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Inject> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Inject>")

if(C2CORE_BUILD_TESTS OR C2CORE_BUILD_FUNCTIONAL_TESTS)
    if(WIN32)
        add_executable(dummyInject tests/dummyInject.cpp)
    endif()
endif()

if(C2CORE_BUILD_TESTS)
    if(WIN32)
        add_executable(testsInject tests/testsInject.cpp Inject.cpp ../ModuleCmd/syscall.cpp ${SYSCALL_OBJ})
        target_link_libraries(testsInject PRIVATE Donut)
        c2core_disable_safeseh_for_x86(testsInject)
        add_dependencies(testsInject dummyInject)
        target_compile_definitions(testsInject PRIVATE C2_INJECT_DUMMY_EXE="$<TARGET_FILE:dummyInject>")
    else()
        add_executable(testsInject tests/testsInject.cpp Inject.cpp)
        target_link_libraries(testsInject PRIVATE Donut ${aplib64} )
    endif()

    add_custom_command(TARGET testsInject POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsInject> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsInject>")

    add_test(NAME testsInject COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsInject>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    if(WIN32)
        add_executable(testsInjectFunctional tests/functional/testsInjectFunctional.cpp Inject.cpp ../ModuleCmd/syscall.cpp ${SYSCALL_OBJ})
        target_link_libraries(testsInjectFunctional PRIVATE Donut)
        c2core_disable_safeseh_for_x86(testsInjectFunctional)
        add_dependencies(testsInjectFunctional dummyInject)
        target_compile_definitions(testsInjectFunctional PRIVATE C2_INJECT_DUMMY_EXE="$<TARGET_FILE:dummyInject>")
    else()
        add_executable(testsInjectFunctional tests/functional/testsInjectFunctional.cpp Inject.cpp)
        target_link_libraries(testsInjectFunctional PRIVATE Donut ${aplib64})
    endif()

    target_include_directories(testsInjectFunctional PRIVATE ../tests)
    add_custom_command(TARGET testsInjectFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:testsInjectFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsInjectFunctional>")

    add_test(NAME testsInjectFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsInjectFunctional>")
    set_tests_properties(testsInjectFunctional PROPERTIES LABELS "functional;inject;local-exec" SKIP_RETURN_CODE 77)
endif()
