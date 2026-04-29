include_directories(../)
add_library(Chisel SHARED Chisel.cpp)

set_property(TARGET Chisel PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

if(C2CORE_BUILD_TESTS)
    target_link_libraries(Chisel PRIVATE Donut )
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

