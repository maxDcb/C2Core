include_directories(../)
add_library(Chisel SHARED Chisel.cpp)

set_property(TARGET Chisel PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

if(C2CORE_BUILD_TESTS)
    target_link_libraries(Chisel PRIVATE Donut )
endif()

if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_executable(testsChiselFunctional tests/functional/testsChiselFunctional.cpp Chisel.cpp)
    target_include_directories(testsChiselFunctional PRIVATE ../tests)
    target_link_libraries(testsChiselFunctional PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(testsChiselFunctional PRIVATE C2CORE_BUILD_FUNCTIONAL_TESTS)
    add_custom_command(TARGET testsChiselFunctional POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsChiselFunctional> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsChiselFunctional>")
    add_test(NAME testsChiselFunctional COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsChiselFunctional>")
    set_tests_properties(testsChiselFunctional PROPERTIES LABELS "functional;chisel;windows-local" SKIP_RETURN_CODE 77)
endif()
c2core_disable_safeseh_for_x86(Chisel)

add_custom_command(TARGET Chisel POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Chisel> "${C2_RUNTIME_MODULE_OUTPUT_DIR}/$<TARGET_FILE_NAME:Chisel>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsChisel tests/testsChisel.cpp Chisel.cpp)

    if(WIN32)
        target_link_libraries(testsChisel PRIVATE Donut )
        c2core_disable_safeseh_for_x86(testsChisel)
    else()
        target_link_libraries(testsChisel PRIVATE Donut ${aplib64} )
    endif()

    add_custom_command(TARGET testsChisel POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsChisel> "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsChisel>")

    add_test(NAME testsChisel COMMAND "${C2_TEST_BIN_OUTPUT_DIR}/$<TARGET_FILE_NAME:testsChisel>")
endif()

