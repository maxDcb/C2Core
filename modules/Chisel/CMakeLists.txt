include_directories(../)
add_library(Chisel SHARED Chisel.cpp)

set_property(TARGET Chisel PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

target_link_libraries(Chisel PRIVATE Donut )

add_custom_command(TARGET Chisel POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Chisel> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Chisel>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsChisel tests/testsChisel.cpp Chisel.cpp)

    if(WIN32)
        target_link_libraries(testsChisel PRIVATE Donut )
    else()
        target_link_libraries(testsChisel PRIVATE Donut ${aplib64} )
    endif()

    add_custom_command(TARGET testsChisel POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsChisel> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsChisel>")

    add_test(NAME testsChisel COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsChisel>")
endif()

