include_directories(../)
add_library(Cat SHARED Cat.cpp)
target_link_libraries(Cat )
add_custom_command(TARGET Cat POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
$<TARGET_FILE:Cat> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:Cat>")

if(WITH_TESTS)
    add_executable(testsCat tests/testsCat.cpp Cat.cpp)
    target_link_libraries(testsCat )
    add_custom_command(TARGET testsCat POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsCat> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsCat>")

    add_test(NAME testsCat COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsCat>")
endif()