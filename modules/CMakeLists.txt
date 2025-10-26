set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(C2CORE_BUILD_TESTS)
    enable_testing()
endif()

include_directories(ModuleCmd)

add_subdirectory(ModuleCmd)

add_subdirectory(PsExec)
add_subdirectory(WmiExec)
add_subdirectory(TaskScheduler)
add_subdirectory(WinRM)
add_subdirectory(DcomExec)
add_subdirectory(CimExec)

