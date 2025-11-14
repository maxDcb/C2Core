add_library(RawWinRm SHARED RawWinRm.cpp ${CMAKE_SOURCE_DIR}/thirdParty/base64/base64.cpp)

if (MSVC)
    set_property(TARGET RawWinRm PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()

if (WIN32)
    target_link_libraries(RawWinRm PRIVATE winhttp ws2_32 crypt32 ole32 advapi32 openssl::openssl)
else()
    find_package(CURL REQUIRED)
    target_link_libraries(RawWinRm PRIVATE CURL::libcurl openssl::openssl)
endif()

add_custom_command(TARGET RawWinRm POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:RawWinRm> "${CMAKE_SOURCE_DIR}/Release/Modules/$<TARGET_FILE_NAME:RawWinRm>")

if(C2CORE_BUILD_TESTS)
    add_executable(testsRawWinRm tests/testsRawWinRm.cpp RawWinRm.cpp ${CMAKE_SOURCE_DIR}/thirdParty/base64/base64.cpp)
    target_compile_definitions(testsRawWinRm PRIVATE RAWWINRM_TEST_BUILD)
    if (WIN32)
        target_link_libraries(testsRawWinRm PRIVATE winhttp ws2_32 crypt32 ole32 advapi32 openssl::openssl)
    else()
        target_link_libraries(testsRawWinRm PRIVATE CURL::libcurl openssl::openssl)
    endif()
    add_custom_command(TARGET testsRawWinRm POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:testsRawWinRm> "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsRawWinRm>")
    add_test(NAME testsRawWinRm COMMAND "${CMAKE_SOURCE_DIR}/Tests/$<TARGET_FILE_NAME:testsRawWinRm>")
endif()
