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

add_subdirectory("${module_dir}/ScreenShot" ScreenShot)
target_link_libraries(ScreenShot c2_base64 nlohmann_json::nlohmann_json)
target_link_libraries(testsScreenShot c2_base64 nlohmann_json::nlohmann_json)
target_compile_definitions(testsScreenShot PRIVATE C2CORE_BUILD_TESTS)

add_executable(testsLocalScreenShotContract
    testsLocalScreenShotContract.cpp
    "${module_dir}/ScreenShot/ScreenShot.cpp"
    "${module_dir}/ScreenShot/ScreenShooter.cpp"
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

foreach(module IN ITEMS Remove Run Shell)
    add_subdirectory("${module_dir}/${module}" "${module}")
    target_link_libraries(${module} c2_base64 nlohmann_json::nlohmann_json)
    target_link_libraries(tests${module} c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(tests${module} PRIVATE C2CORE_BUILD_TESTS)
endforeach()
if(UNIX AND NOT APPLE)
    find_library(C2_UTIL_LIBRARY util)
    if(C2_UTIL_LIBRARY)
        target_link_libraries(Shell ${C2_UTIL_LIBRARY})
        target_link_libraries(testsShell ${C2_UTIL_LIBRARY})
    endif()
endif()

add_executable(testsLocalCommandModuleContract
    testsLocalCommandModuleContract.cpp
    "${module_dir}/Remove/Remove.cpp"
    "${module_dir}/Run/Run.cpp"
    "${module_dir}/Shell/Shell.cpp"
)
target_compile_definitions(testsLocalCommandModuleContract PRIVATE BUILD_TEAMSERVER
    REMOVE_MODULE_PATH="$<TARGET_FILE:Remove>"
    RUN_MODULE_PATH="$<TARGET_FILE:Run>"
    SHELL_MODULE_PATH="$<TARGET_FILE:Shell>")
target_link_libraries(testsLocalCommandModuleContract PRIVATE c2_base64 nlohmann_json::nlohmann_json ${CMAKE_DL_LIBS})
add_dependencies(testsLocalCommandModuleContract Remove Run Shell)
if(UNIX AND NOT APPLE AND C2_UTIL_LIBRARY)
    target_link_libraries(testsLocalCommandModuleContract PRIVATE ${C2_UTIL_LIBRARY})
endif()
add_test(NAME testsLocalCommandModuleContract COMMAND testsLocalCommandModuleContract)

foreach(module IN ITEMS KillProcess Script)
    add_subdirectory("${module_dir}/${module}" "${module}")
    target_link_libraries(${module} c2_base64 nlohmann_json::nlohmann_json)
    target_link_libraries(tests${module} c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(tests${module} PRIVATE C2CORE_BUILD_TESTS)
endforeach()

add_executable(testsLocalProcessModuleContract
    testsLocalProcessModuleContract.cpp
    "${module_dir}/KillProcess/KillProcess.cpp"
    "${module_dir}/Script/Script.cpp"
)
target_compile_definitions(testsLocalProcessModuleContract PRIVATE BUILD_TEAMSERVER
    KILLPROCESS_MODULE_PATH="$<TARGET_FILE:KillProcess>"
    SCRIPT_MODULE_PATH="$<TARGET_FILE:Script>")
target_link_libraries(testsLocalProcessModuleContract PRIVATE c2_base64 nlohmann_json::nlohmann_json ${CMAKE_DL_LIBS})
add_dependencies(testsLocalProcessModuleContract KillProcess Script)
add_test(NAME testsLocalProcessModuleContract COMMAND testsLocalProcessModuleContract)

add_subdirectory("${module_dir}/EnumerateShares" EnumerateShares)
target_link_libraries(EnumerateShares c2_base64 nlohmann_json::nlohmann_json)
target_link_libraries(testsEnumerateShares c2_base64 nlohmann_json::nlohmann_json)
target_compile_definitions(testsEnumerateShares PRIVATE C2CORE_BUILD_TESTS)

add_executable(testsLocalShareModuleContract
    testsLocalShareModuleContract.cpp
    "${module_dir}/EnumerateShares/EnumerateShares.cpp"
)
target_compile_definitions(testsLocalShareModuleContract PRIVATE BUILD_TEAMSERVER
    ENUMERATESHARES_MODULE_PATH="$<TARGET_FILE:EnumerateShares>")
target_link_libraries(testsLocalShareModuleContract PRIVATE c2_base64 nlohmann_json::nlohmann_json ${CMAKE_DL_LIBS})
add_dependencies(testsLocalShareModuleContract EnumerateShares)
if(UNIX AND NOT APPLE)
    target_link_libraries(testsLocalShareModuleContract PRIVATE smbclient)
endif()
add_test(NAME testsLocalShareModuleContract COMMAND testsLocalShareModuleContract)

add_subdirectory("${module_dir}/ReversePortForward" ReversePortForward)
target_link_libraries(ReversePortForward c2_base64 nlohmann_json::nlohmann_json)
target_link_libraries(testsReversePortForward c2_base64 nlohmann_json::nlohmann_json)
target_compile_definitions(testsReversePortForward PRIVATE C2CORE_BUILD_TESTS)

add_executable(testsLocalForwardModuleContract
    testsLocalForwardModuleContract.cpp
    "${module_dir}/ReversePortForward/ReversePortForward.cpp"
)
target_compile_definitions(testsLocalForwardModuleContract PRIVATE BUILD_TEAMSERVER
    REVERSEPORTFORWARD_MODULE_PATH="$<TARGET_FILE:ReversePortForward>")
target_link_libraries(testsLocalForwardModuleContract PRIVATE c2_base64 nlohmann_json::nlohmann_json ${CMAKE_DL_LIBS})
add_dependencies(testsLocalForwardModuleContract ReversePortForward)
if(WIN32)
    target_link_libraries(testsLocalForwardModuleContract PRIVATE ws2_32)
endif()
add_test(NAME testsLocalForwardModuleContract COMMAND testsLocalForwardModuleContract)

add_subdirectory("${module_dir}/EnumerateRdpSessions" EnumerateRdpSessions)
target_link_libraries(EnumerateRdpSessions PRIVATE c2_base64 nlohmann_json::nlohmann_json)
target_link_libraries(testsEnumerateRdpSessions PRIVATE c2_base64 nlohmann_json::nlohmann_json)
target_compile_definitions(testsEnumerateRdpSessions PRIVATE C2CORE_BUILD_TESTS)

add_executable(testsLocalRdpModuleContract
    testsLocalRdpModuleContract.cpp
    "${module_dir}/EnumerateRdpSessions/EnumerateRdpSessions.cpp"
)
target_compile_definitions(testsLocalRdpModuleContract PRIVATE BUILD_TEAMSERVER
    ENUMERATERDPSESSIONS_MODULE_PATH="$<TARGET_FILE:EnumerateRdpSessions>")
target_link_libraries(testsLocalRdpModuleContract PRIVATE c2_base64 nlohmann_json::nlohmann_json ${CMAKE_DL_LIBS})
add_dependencies(testsLocalRdpModuleContract EnumerateRdpSessions)
if(WIN32)
    target_compile_definitions(testsLocalRdpModuleContract PRIVATE _WIN32_WINNT=0x0601)
    target_link_libraries(testsLocalRdpModuleContract PRIVATE Wtsapi32)
endif()
add_test(NAME testsLocalRdpModuleContract COMMAND testsLocalRdpModuleContract)

add_subdirectory("${module_dir}/Registry" Registry)
target_link_libraries(Registry PRIVATE c2_base64 nlohmann_json::nlohmann_json)
target_link_libraries(testsRegistry PRIVATE c2_base64 nlohmann_json::nlohmann_json)
target_compile_definitions(testsRegistry PRIVATE C2CORE_BUILD_TESTS)

add_executable(testsLocalRegistryModuleContract
    testsLocalRegistryModuleContract.cpp
    "${module_dir}/Registry/Registry.cpp"
)
target_compile_definitions(testsLocalRegistryModuleContract PRIVATE BUILD_TEAMSERVER
    REGISTRY_MODULE_PATH="$<TARGET_FILE:Registry>")
target_link_libraries(testsLocalRegistryModuleContract PRIVATE c2_base64 nlohmann_json::nlohmann_json ${CMAKE_DL_LIBS})
add_dependencies(testsLocalRegistryModuleContract Registry)
if(WIN32)
    target_compile_definitions(testsLocalRegistryModuleContract PRIVATE _WIN32_WINNT=0x0601)
    target_link_libraries(testsLocalRegistryModuleContract PRIVATE Advapi32)
endif()
add_test(NAME testsLocalRegistryModuleContract COMMAND testsLocalRegistryModuleContract)

add_subdirectory("${module_dir}/WinRM" WinRM)
target_link_libraries(WinRM PRIVATE c2_base64 nlohmann_json::nlohmann_json)
target_link_libraries(testsWinRM PRIVATE c2_base64 nlohmann_json::nlohmann_json)
target_compile_definitions(testsWinRM PRIVATE C2CORE_BUILD_TESTS)
if(C2CORE_BUILD_FUNCTIONAL_TESTS)
    target_link_libraries(testsWinRMFunctional PRIVATE c2_base64 nlohmann_json::nlohmann_json)
endif()

foreach(module IN ITEMS MakeToken Rev2self StealToken)
    add_subdirectory("${module_dir}/${module}" "${module}")
    target_link_libraries(${module} PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    target_link_libraries(tests${module} PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(tests${module} PRIVATE C2CORE_BUILD_TESTS)
endforeach()

set(C2_DONUT_INCLUDE_DIR "${module_dir}/../../thirdParty/donut/include" CACHE PATH "Directory containing donut.h")
if(NOT EXISTS "${C2_DONUT_INCLUDE_DIR}/donut.h")
    message(FATAL_ERROR "Set C2_DONUT_INCLUDE_DIR to the directory containing donut.h for WmiExec.")
endif()
include_directories("${C2_DONUT_INCLUDE_DIR}")

foreach(module IN ITEMS WmiExec CimExec TaskScheduler)
    add_subdirectory("${module_dir}/${module}" "${module}")
    target_link_libraries(${module} PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    target_link_libraries(tests${module} PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    target_compile_definitions(tests${module} PRIVATE C2CORE_BUILD_TESTS)
endforeach()

foreach(module IN ITEMS DcomExec PsExec SpawnAs)
    add_subdirectory("${module_dir}/${module}" "${module}")
    if(module STREQUAL "DcomExec")
        target_link_libraries(${module} PRIVATE c2_base64 nlohmann_json::nlohmann_json)
        target_link_libraries(tests${module} PRIVATE c2_base64 nlohmann_json::nlohmann_json)
    else()
        target_link_libraries(${module} c2_base64 nlohmann_json::nlohmann_json)
        target_link_libraries(tests${module} c2_base64 nlohmann_json::nlohmann_json)
    endif()
    target_compile_definitions(tests${module} PRIVATE C2CORE_BUILD_TESTS)
    if(C2CORE_BUILD_FUNCTIONAL_TESTS)
        if(module STREQUAL "DcomExec")
            target_link_libraries(tests${module}Functional PRIVATE c2_base64 nlohmann_json::nlohmann_json)
        else()
            target_link_libraries(tests${module}Functional c2_base64 nlohmann_json::nlohmann_json)
        endif()
        target_compile_definitions(tests${module}Functional PRIVATE C2CORE_BUILD_FUNCTIONAL_TESTS)
    endif()
endforeach()

add_executable(testsLocalWindowsExecContract
    testsLocalWindowsExecContract.cpp
    "${module_dir}/DcomExec/DcomExec.cpp"
    "${module_dir}/PsExec/PsExec.cpp"
    "${module_dir}/SpawnAs/SpawnAs.cpp"
)
target_compile_definitions(testsLocalWindowsExecContract PRIVATE BUILD_TEAMSERVER)
target_link_libraries(testsLocalWindowsExecContract PRIVATE c2_base64 nlohmann_json::nlohmann_json)
if(WIN32)
    target_compile_definitions(testsLocalWindowsExecContract PRIVATE _WIN32_WINNT=0x0601)
    target_link_libraries(testsLocalWindowsExecContract PRIVATE ole32 oleaut32 advapi32 userenv)
endif()
add_test(NAME testsLocalWindowsExecContract COMMAND testsLocalWindowsExecContract)
