include_directories(../)
add_library(Inject SHARED Inject.cpp)
if(WITH_TESTS)
    message(STATUS "[+] Inject Tests are enable.")
    target_link_libraries(Inject ${Donut} )
else()
    message(STATUS "[-] Inject Tests are disable.")   
    target_link_libraries(Inject ${Donut} ) 
endif()
add_custom_command(TARGET Inject POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Inject> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Inject>")

if(WITH_TESTS)
    add_executable(testsInject tests/testsInject.cpp Inject.cpp)

    if(WIN32)
        target_link_libraries(testsInject ${Donut} )
    else()
        target_link_libraries(testsInject ${Donut} ${aplib64} )
    endif()

    add_custom_command(TARGET testsInject POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsInject> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsInject>")

    add_test(NAME testsInject COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsInject>")
endif()