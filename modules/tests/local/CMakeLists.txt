cmake_minimum_required(VERSION 3.20)
project(C2CoreLocalModuleTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)

find_package(nlohmann_json CONFIG REQUIRED)
set(C2_BASE64_SOURCE_DIR "" CACHE PATH "Directory containing cpp-base64 sources")
if(NOT EXISTS "${C2_BASE64_SOURCE_DIR}/base64.cpp" OR NOT EXISTS "${C2_BASE64_SOURCE_DIR}/base64.h")
    message(FATAL_ERROR "Set C2_BASE64_SOURCE_DIR to the directory containing base64.cpp and base64.h.")
endif()

add_library(c2_base64 STATIC "${C2_BASE64_SOURCE_DIR}/base64.cpp")
target_include_directories(c2_base64 PUBLIC "${C2_BASE64_SOURCE_DIR}")
set_target_properties(c2_base64 PROPERTIES POSITION_INDEPENDENT_CODE ON)

enable_testing()
set(C2CORE_BUILD_TESTS ON)
set(C2_RUNTIME_MODULE_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/modules")
set(C2_TEST_BIN_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/tests")
file(MAKE_DIRECTORY "${C2_RUNTIME_MODULE_OUTPUT_DIR}" "${C2_TEST_BIN_OUTPUT_DIR}")

set(module_dir "${CMAKE_CURRENT_SOURCE_DIR}/../..")
include_directories("${module_dir}/ModuleCmd")

foreach(module IN ITEMS Cat Tree)
    add_subdirectory("${module_dir}/${module}" "${module}")
    target_link_libraries(${module} c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(tests${module} PRIVATE C2CORE_BUILD_TESTS)
endforeach()

add_subdirectory("${module_dir}/ModuleTemplate" ModuleTemplate)

foreach(module IN ITEMS MkDir ListDirectory ChangeDirectory PrintWorkingDirectory)
    add_subdirectory("${module_dir}/${module}" "${module}")
    target_link_libraries(${module} c2_base64 nlohmann_json::nlohmann_json)
    target_link_libraries(tests${module} c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(tests${module} PRIVATE C2CORE_BUILD_TESTS)
endforeach()

add_executable(testsLocalFileModuleContract
    testsLocalFileModuleContract.cpp
    "${module_dir}/MkDir/MkDir.cpp"
    "${module_dir}/ListDirectory/ListDirectory.cpp"
    "${module_dir}/ChangeDirectory/ChangeDirectory.cpp"
    "${module_dir}/PrintWorkingDirectory/PrintWorkingDirectory.cpp"
)
target_compile_definitions(testsLocalFileModuleContract PRIVATE BUILD_TEAMSERVER)
target_link_libraries(testsLocalFileModuleContract PRIVATE c2_base64 nlohmann_json::nlohmann_json)
add_test(NAME testsLocalFileModuleContract COMMAND testsLocalFileModuleContract)

foreach(module IN ITEMS GetEnv Whoami HostContext)
    add_subdirectory("${module_dir}/${module}" "${module}")
    if(module STREQUAL "HostContext")
        target_link_libraries(${module} PRIVATE c2_base64 nlohmann_json::nlohmann_json)
        target_link_libraries(tests${module} PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    else()
        target_link_libraries(${module} c2_base64 nlohmann_json::nlohmann_json)
        target_link_libraries(tests${module} c2_base64 nlohmann_json::nlohmann_json)
    endif()
    target_compile_definitions(tests${module} PRIVATE C2CORE_BUILD_TESTS)
endforeach()

add_executable(testsLocalIdentityModuleContract
    testsLocalIdentityModuleContract.cpp
    "${module_dir}/GetEnv/GetEnv.cpp"
    "${module_dir}/Whoami/Whoami.cpp"
    "${module_dir}/HostContext/HostContext.cpp"
)
target_compile_definitions(testsLocalIdentityModuleContract PRIVATE BUILD_TEAMSERVER)
target_link_libraries(testsLocalIdentityModuleContract PRIVATE c2_base64 nlohmann_json::nlohmann_json)
if(WIN32)
    target_link_libraries(testsLocalIdentityModuleContract PRIVATE iphlpapi Advapi32)
endif()
add_test(NAME testsLocalIdentityModuleContract COMMAND testsLocalIdentityModuleContract)

foreach(module IN ITEMS IpConfig Netstat ListProcesses)
    add_subdirectory("${module_dir}/${module}" "${module}")
    target_link_libraries(${module} c2_base64 nlohmann_json::nlohmann_json)
    target_link_libraries(tests${module} c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(tests${module} PRIVATE C2CORE_BUILD_TESTS)
    if(WIN32 AND (module STREQUAL "IpConfig" OR module STREQUAL "Netstat"))
        target_link_libraries(${module} iphlpapi ws2_32)
        target_link_libraries(tests${module} iphlpapi ws2_32)
    endif()
endforeach()

add_executable(testsLocalSystemModuleContract
    testsLocalSystemModuleContract.cpp
    "${module_dir}/IpConfig/IpConfig.cpp"
    "${module_dir}/Netstat/Netstat.cpp"
    "${module_dir}/ListProcesses/ListProcesses.cpp"
)
target_compile_definitions(testsLocalSystemModuleContract PRIVATE BUILD_TEAMSERVER)
target_compile_definitions(testsLocalSystemModuleContract PRIVATE
    IPCONFIG_MODULE_PATH="$<TARGET_FILE:IpConfig>"
    NETSTAT_MODULE_PATH="$<TARGET_FILE:Netstat>"
    LISTPROCESSES_MODULE_PATH="$<TARGET_FILE:ListProcesses>"
)
target_link_libraries(testsLocalSystemModuleContract PRIVATE c2_base64 nlohmann_json::nlohmann_json ${CMAKE_DL_LIBS})
add_dependencies(testsLocalSystemModuleContract IpConfig Netstat ListProcesses)
if(WIN32)
    target_link_libraries(testsLocalSystemModuleContract PRIVATE iphlpapi ws2_32)
endif()
add_test(NAME testsLocalSystemModuleContract COMMAND testsLocalSystemModuleContract)

add_subdirectory("${module_dir}/Screenshot" ScreenShot)
target_link_libraries(ScreenShot c2_base64 nlohmann_json::nlohmann_json)
target_link_libraries(testsScreenShot c2_base64 nlohmann_json::nlohmann_json)
target_compile_definitions(testsScreenShot PRIVATE C2CORE_BUILD_TESTS)

add_executable(testsLocalScreenShotContract
    testsLocalScreenShotContract.cpp
    "${module_dir}/Screenshot/ScreenShot.cpp"
    "${module_dir}/Screenshot/ScreenShooter.cpp"
)
target_compile_definitions(testsLocalScreenShotContract PRIVATE
    BUILD_TEAMSERVER C2CORE_BUILD_TESTS C2CORE_SCREENSHOT_TEST_PAYLOAD
    SCREENSHOT_MODULE_PATH="$<TARGET_FILE:ScreenShot>")
target_link_libraries(testsLocalScreenShotContract PRIVATE c2_base64 nlohmann_json::nlohmann_json ${CMAKE_DL_LIBS})
add_dependencies(testsLocalScreenShotContract ScreenShot)
if(WIN32)
    target_link_libraries(testsLocalScreenShotContract PRIVATE gdiplus ole32)
endif()
add_test(NAME testsLocalScreenShotContract COMMAND testsLocalScreenShotContract)

foreach(module IN ITEMS Download Upload)
    add_subdirectory("${module_dir}/${module}" "${module}")
    target_link_libraries(${module} c2_base64 nlohmann_json::nlohmann_json)
    target_link_libraries(tests${module} c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(tests${module} PRIVATE C2CORE_BUILD_TESTS)
endforeach()

add_executable(testsLocalTransferModuleContract
    testsLocalTransferModuleContract.cpp
    "${module_dir}/Download/Download.cpp"
    "${module_dir}/Upload/Upload.cpp"
)
target_compile_definitions(testsLocalTransferModuleContract PRIVATE BUILD_TEAMSERVER
    DOWNLOAD_MODULE_PATH="$<TARGET_FILE:Download>"
    UPLOAD_MODULE_PATH="$<TARGET_FILE:Upload>")
target_link_libraries(testsLocalTransferModuleContract PRIVATE c2_base64 nlohmann_json::nlohmann_json ${CMAKE_DL_LIBS})
add_dependencies(testsLocalTransferModuleContract Download Upload)
add_test(NAME testsLocalTransferModuleContract COMMAND testsLocalTransferModuleContract)
