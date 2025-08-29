cmake_minimum_required(VERSION 3.16)
project(C2Core LANGUAGES CXX)

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

FetchContent_Declare(
  SocketHandler
  GIT_REPOSITORY https://github.com/maxDcb/libSocketHandler.git
  GIT_TAG master
)
FetchContent_MakeAvailable(SocketHandler)

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

FetchContent_Declare(
  SocksServer
  GIT_REPOSITORY https://github.com/maxDcb/libSocks5.git
  GIT_TAG master
)
FetchContent_MakeAvailable(SocksServer)

# Header-only / source dependencies placed in thirdParty for relative includes
set(BASE64_SRC_DIR ${CMAKE_SOURCE_DIR}/thirdParty/base64)
FetchContent_Declare(
  base64
  GIT_REPOSITORY https://github.com/ReneNyffenegger/cpp-base64.git
  GIT_TAG 82147d6d89636217b870f54ec07ddd3e544d5f69
  SOURCE_DIR ${BASE64_SRC_DIR}
)
FetchContent_Populate(base64)

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

option(BUILD_TESTING "Build unit tests" ON)
if(BUILD_TESTING)
  enable_testing()
  set(WITH_TESTS ON CACHE BOOL "" FORCE)
endif()

add_subdirectory(beacon/tests)
add_subdirectory(listener/tests)
add_subdirectory(modules)
