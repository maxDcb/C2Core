include_directories(../)
add_library(Chisel SHARED Chisel.cpp)
if(WITH_TESTS)
    message(STATUS "[+] Chisel Tests are enable.")
    target_link_libraries(Chisel ${Donut} )
else()
    message(STATUS "[-] Chisel Tests are disable.")    
    target_link_libraries(Chisel ${Donut} )
endif()
add_custom_command(TARGET Chisel POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Chisel> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Chisel>")

if(WITH_TESTS)
    add_executable(testsChisel tests/testsChisel.cpp Chisel.cpp)

    if(WIN32)
        target_link_libraries(testsChisel ${Donut} )
    else()
        target_link_libraries(testsChisel ${Donut} ${aplib64} )
    endif()

    add_custom_command(TARGET testsChisel POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsChisel> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsChisel>")

    add_test(NAME testsChisel COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsChisel>")
endif()

