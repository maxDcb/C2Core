
if(WITH_TESTS)
    add_executable(testsModuleCmd tests/testsModuleCmd.cpp ../../../thirdParty/base64/base64.cpp)
    target_link_libraries(testsModuleCmd )
    add_custom_command(TARGET testsModuleCmd POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsModuleCmd> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsModuleCmd>")
    add_test(NAME testsModuleCmd COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsModuleCmd>")

    add_executable(testsTools tests/testsTools.cpp ../../../thirdParty/base64/base64.cpp)
    target_link_libraries(testsTools )
    add_custom_command(TARGET testsTools POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
    $<TARGET_FILE:testsTools> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsTools>")
    add_test(NAME testsTools COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsTools>")

    if(WIN32)
        add_executable(testsSyscall tests/testsSyscall.cpp ./syscall.cpp ./syscall.x64.obj)
        target_link_libraries(testsSyscall )
        add_custom_command(TARGET testsSyscall POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
        $<TARGET_FILE:testsSyscall> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsSyscall>")
        add_test(NAME testsSyscall COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsSyscall>")

        add_executable(testsHwbp tests/testsHwbp.cpp ./hwbp.cpp ./peb.cpp)
        target_link_libraries(testsHwbp )
        add_custom_command(TARGET testsHwbp POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy 
        $<TARGET_FILE:testsHwbp> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsHwbp>")
        add_test(NAME testsHwbp COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsHwbp>")
    endif()
endif()