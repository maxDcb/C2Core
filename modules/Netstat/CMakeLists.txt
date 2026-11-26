include_directories(../)
add_library(Netstat SHARED Netstat.cpp)
set_property(TARGET Netstat PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(Netstat )
add_custom_command(TARGET Netstat POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:Netstat> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Netstat>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsNetstat tests/testsNetstat.cpp Netstat.cpp)
    target_link_libraries(testsNetstat )
    add_custom_command(TARGET testsNetstat POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsNetstat> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsNetstat>")
    add_test(NAME testsNetstat COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsNetstat>")
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_executable(testsNetstatFunctional tests/functional/testsNetstatFunctional.cpp Netstat.cpp)
    target_include_directories(testsNetstatFunctional PRIVATE ../tests)
    target_link_libraries(testsNetstatFunctional PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(testsNetstatFunctional PRIVATE C2CORE_BUILD_FUNCTIONAL_TESTS)
    if(WIN32)
        target_link_libraries(testsNetstatFunctional PRIVATE ws2_32 iphlpapi)
    endif()
    add_custom_command(TARGET testsNetstatFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsNetstatFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsNetstatFunctional>")
    add_test(NAME testsNetstatFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsNetstatFunctional>")
    set_tests_properties(testsNetstatFunctional PROPERTIES LABELS "functional;netstat;local")
endif()
