add_library(RawWinRm SHARED RawWinRm.cpp)
set_property(TARGET RawWinRm PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

target_link_libraries(RawWinRm PRIVATE ModuleCmd)

if (WIN32)
    target_link_libraries(RawWinRm PRIVATE winhttp ws2_32 crypt32 ole32 advapi32)
endif()

add_custom_command(TARGET RawWinRm POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:RawWinRm> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:RawWinRm>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsRawWinRm tests/testsRawWinRm.cpp RawWinRm.cpp)
    target_link_libraries(testsRawWinRm PRIVATE ModuleCmd)
    if (WIN32)
        target_link_libraries(testsRawWinRm PRIVATE winhttp ws2_32 crypt32 ole32 advapi32)
    endif()
    add_custom_command(TARGET testsRawWinRm POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsRawWinRm> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsRawWinRm>")
    add_test(NAME testsRawWinRm COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsRawWinRm>")
endif()
