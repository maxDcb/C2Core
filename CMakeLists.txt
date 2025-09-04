cmake_minimum_required(VERSION 3.16)
project(C2Core LANGUAGES CXX)

# --- Use the static MSVC runtime (/MT, /MTd) everywhere on Windows ---
if(MSVC)
  # Make CMAKE_MSVC_RUNTIME_LIBRARY authoritative
  cmake_policy(SET CMP0091 NEW)
  # Use /MT for Release-like configs and /MTd for Debug
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>" CACHE STRING "" FORCE)

  # (Optional) clean any /MD that third-parties might have injected into global flags
  foreach(flag_var
          CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_C_FLAGS_MINSIZEREL
          CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_MINSIZEREL)
    if(DEFINED ${flag_var})
      string(REGEX REPLACE "/MDd" "" ${flag_var} "${${flag_var}}")
      string(REGEX REPLACE "/MD"  "" ${flag_var} "${${flag_var}}")
    endif()
  endforeach()

  add_compile_definitions(
    NOMINMAX                # <-- disables Windows min/max macros
  )
endif()
# --------------------------------------------------------------------

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# External libraries
FetchContent_Declare(
  Dnscommunication
  GIT_REPOSITORY https://github.com/maxDcb/Dnscommunication.git
  GIT_TAG master
)
FetchContent_MakeAvailable(Dnscommunication)
set_target_properties(Dnscommunication PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "$<BUILD_INTERFACE:${dnscommunication_SOURCE_DIR}/src>;$<INSTALL_INTERFACE:include>")

FetchContent_Declare(
  SocketHandler
  GIT_REPOSITORY https://github.com/maxDcb/libSocketHandler.git
  GIT_TAG master
)
FetchContent_MakeAvailable(SocketHandler)
set_target_properties(SocketHandler PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "$<BUILD_INTERFACE:${sockethandler_SOURCE_DIR}/src>;$<INSTALL_INTERFACE:include>")

# PipeHandler and MemoryModule have platform-specific sources
if(WIN32)
  FetchContent_Declare(
    PipeHandler
    GIT_REPOSITORY https://github.com/maxDcb/libPipeHandler.git
    GIT_TAG master
  )
  FetchContent_Declare(
    MemoryModule
    GIT_REPOSITORY https://github.com/maxDcb/MemoryModule.git
    GIT_TAG master
  )
else()
  FetchContent_Declare(
    PipeHandler
    GIT_REPOSITORY https://github.com/maxDcb/C2TeamServer.git
    GIT_TAG master
    SOURCE_SUBDIR libs/libPipeHandlerDumy
  )
  FetchContent_Declare(
    MemoryModule
    GIT_REPOSITORY https://github.com/maxDcb/C2TeamServer.git
    GIT_TAG master
    SOURCE_SUBDIR libs/libMemoryModuleDumy
  )
endif()

FetchContent_MakeAvailable(PipeHandler)
FetchContent_MakeAvailable(MemoryModule)
if(WIN32)
  set(_pipe_inc ${pipehandler_SOURCE_DIR}/src)
  set(_mm_inc   ${memorymodule_SOURCE_DIR}/)
else()
  set(_pipe_inc ${pipehandler_SOURCE_DIR}/libs/libPipeHandlerDumy/src)
  set(_mm_inc   ${memorymodule_SOURCE_DIR}/libs/libMemoryModuleDumy/src)
endif()
set_target_properties(PipeHandler PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "$<BUILD_INTERFACE:${_pipe_inc}>;$<INSTALL_INTERFACE:include>")
set_target_properties(MemoryModule PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "$<BUILD_INTERFACE:${_mm_inc}>;$<INSTALL_INTERFACE:include>")

FetchContent_Declare(
  SocksServer
  GIT_REPOSITORY https://github.com/maxDcb/libSocks5.git
  GIT_TAG master
)
FetchContent_MakeAvailable(SocksServer)
set_target_properties(SocksServer PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "$<BUILD_INTERFACE:${socksserver_SOURCE_DIR}/src>;$<INSTALL_INTERFACE:include>")

if(WIN32)
  FetchContent_Declare(
    CoffPacker
    GIT_REPOSITORY https://github.com/maxDcb/COFFPacker.git
    GIT_TAG master
  )
  FetchContent_Declare(
    CoffLoader
    GIT_REPOSITORY https://github.com/maxDcb/COFFLoader.git
    GIT_TAG main
  )
  FetchContent_MakeAvailable(CoffPacker CoffLoader)
endif()

# Header-only / source dependencies placed in thirdParty for relative includes
set(BASE64_SRC_DIR ${CMAKE_SOURCE_DIR}/thirdParty/base64)
FetchContent_Declare(
  base64
  GIT_REPOSITORY https://github.com/ReneNyffenegger/cpp-base64.git
  GIT_TAG 82147d6d89636217b870f54ec07ddd3e544d5f69
  SOURCE_DIR ${BASE64_SRC_DIR}
)
FetchContent_Populate(base64)
include_directories(${BASE64_SRC_DIR})

set(DONUT_SRC_DIR ${CMAKE_SOURCE_DIR}/thirdParty/donut)
FetchContent_Declare(
  donut
  GIT_REPOSITORY https://github.com/maxDcb/donut.git
  GIT_TAG master
  SOURCE_DIR ${DONUT_SRC_DIR}
)
FetchContent_Populate(donut)

# Additional third party libraries
FetchContent_Declare(
  httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG v0.14.1
)
FetchContent_MakeAvailable(httplib)

find_package(OpenSSL REQUIRED)
add_library(openssl::openssl INTERFACE IMPORTED)
target_link_libraries(openssl::openssl INTERFACE OpenSSL::SSL OpenSSL::Crypto)

# Build tests only when explicitly enabled. Default to ON when C2Core is the
# top-level project and OFF when included from another build.
option(C2CORE_BUILD_TESTS "Build C2Core unit tests" OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(C2CORE_BUILD_TESTS ON CACHE BOOL "Build C2Core unit tests" FORCE)
endif()

if(C2CORE_BUILD_TESTS)
  enable_testing()

  FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.4.0
  )
  FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.2
  )
  FetchContent_MakeAvailable(Catch2 nlohmann_json)
  include_directories(${nlohmann_json_SOURCE_DIR}/include)

  add_subdirectory(beacon/tests)
  add_subdirectory(listener/tests)
endif()

add_subdirectory(beacon)
add_subdirectory(modules)

install(
  DIRECTORY beacon/ listener/ modules/ModuleCmd/ ${socksserver_SOURCE_DIR}/src/
  DESTINATION include
  FILES_MATCHING PATTERN "Beacon*.hpp" 
                 PATTERN "Listener*.hpp" 
                 PATTERN "CommonCommand.hpp" 
                 PATTERN "ModuleCmd.hpp" 
                 PATTERN "C2Message.hpp"
                 PATTERN "Session.hpp"
                 PATTERN "Common.hpp"
                 PATTERN "nlohmann/json.hpp"
                 PATTERN "SocksDef.hpp"
                 PATTERN "SocksTunnelClient.hpp"
)

include(CMakePackageConfigHelpers)
install(EXPORT C2CoreTargets FILE C2CoreTargets.cmake NAMESPACE "" DESTINATION lib/cmake/C2Core)
configure_package_config_file(
  cmake/C2CoreConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/C2CoreConfig.cmake
  INSTALL_DESTINATION lib/cmake/C2Core
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/C2CoreConfig.cmake DESTINATION lib/cmake/C2Core)
