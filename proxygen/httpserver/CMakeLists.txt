# Copyright (c) Facebook, Inc. and its affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

add_library(
    proxygenhttpserver
    RequestHandlerAdaptor.cpp
    SignalHandler.cpp
    HTTPServerAcceptor.cpp
    HTTPServer.cpp
)
target_compile_options(
    proxygenhttpserver
    PRIVATE
        ${_PROXYGEN_COMMON_COMPILE_OPTIONS}
)
if (BUILD_SHARED_LIBS)
    set_property(TARGET proxygenhttpserver PROPERTY POSITION_INDEPENDENT_CODE ON)
    if (DEFINED PACKAGE_VERSION)
        set_target_properties(proxygenhttpserver PROPERTIES VERSION ${PACKAGE_VERSION})
    endif()
endif()

target_link_libraries(
    proxygenhttpserver
    PUBLIC
        proxygen
)
install(
    TARGETS proxygenhttpserver
    EXPORT proxygen-exports
    DESTINATION ${LIB_INSTALL_DIR}
)

add_executable(proxygen_push
    samples/push/PushServer.cpp
    samples/push/PushRequestHandler.cpp
)
target_compile_options(
    proxygen_push
    PRIVATE
        ${_PROXYGEN_COMMON_COMPILE_OPTIONS}
)
target_link_libraries(
    proxygen_push
    PUBLIC
        proxygen
        proxygenhttpserver
)
install(
    TARGETS proxygen_push
    EXPORT proxygen-exports
    DESTINATION bin
)

add_executable(proxygen_proxy
    samples/proxy/ProxyServer.cpp
    samples/proxy/ProxyHandler.cpp
)
target_compile_options(
    proxygen_proxy
    PRIVATE
        ${_PROXYGEN_COMMON_COMPILE_OPTIONS}
)
target_link_libraries(
    proxygen_proxy
    PUBLIC
        proxygen
        proxygenhttpserver
)
install(
    TARGETS proxygen_proxy
    EXPORT proxygen-exports
    DESTINATION bin
)

add_executable(proxygen_static
    samples/static/StaticServer.cpp
    samples/static/StaticHandler.cpp
)
target_compile_options(
    proxygen_static
    PRIVATE
        ${_PROXYGEN_COMMON_COMPILE_OPTIONS}
)
target_link_libraries(
    proxygen_static
    PUBLIC
        proxygen
        proxygenhttpserver
)
install(
    TARGETS proxygen_static
    EXPORT proxygen-exports
    DESTINATION bin
)

add_executable(proxygen_echo
    samples/echo/EchoServer.cpp
    samples/echo/EchoHandler.cpp
)
target_compile_options(
    proxygen_echo
    PRIVATE
        ${_PROXYGEN_COMMON_COMPILE_OPTIONS}
)
target_link_libraries(
    proxygen_echo
    PUBLIC
        proxygen
        proxygenhttpserver
)
install(
    TARGETS proxygen_echo
    EXPORT proxygen-exports
    DESTINATION bin
)

if (BUILD_QUIC)
  add_executable(hq
      samples/hq/main.cpp
      samples/hq/FizzContext.cpp
      samples/hq/HQClient.cpp
      samples/hq/HQLoggerHelper.cpp
      samples/hq/HQServer.cpp
      samples/hq/HQParams.cpp
      samples/hq/SampleHandlers.cpp
  )
  target_compile_options(
      hq
      PRIVATE
          ${_PROXYGEN_COMMON_COMPILE_OPTIONS}
  )
  target_link_libraries(
      hq
      PUBLIC
          proxygen
          proxygencurl
          proxygenhttpserver
          mvfst::mvfst_transport
          mvfst::mvfst_client
          mvfst::mvfst_server
  )
  install(
      TARGETS hq
      EXPORT proxygen-exports
      DESTINATION bin
  )
  add_executable(fbtcp_trafficgen
      samples/fbtcp_trafficgen/main.cpp
      samples/fbtcp_trafficgen/FizzContext.cpp
      samples/fbtcp_trafficgen/HQLoggerHelper.cpp
      samples/fbtcp_trafficgen/HQParams.cpp
      samples/fbtcp_trafficgen/HQServer.cpp
      samples/fbtcp_trafficgen/PartiallyReliableCurlClient.cpp
      samples/fbtcp_trafficgen/SampleHandlers.cpp
      samples/fbtcp_trafficgen/TrafficGenerator.cpp
      samples/fbtcp_trafficgen/TGConnection.cpp
      samples/fbtcp_trafficgen/GETHandler.cpp
      samples/fbtcp_trafficgen/Utils.cpp
  )
  target_compile_options(
      fbtcp_trafficgen
      PRIVATE
          ${_PROXYGEN_COMMON_COMPILE_OPTIONS}
  )
  target_link_libraries(
      fbtcp_trafficgen
      PUBLIC
          proxygen
          proxygencurl
          proxygenhttpserver
          mvfst::mvfst_transport
          mvfst::mvfst_client
          mvfst::mvfst_server
  )
  install(
      TARGETS fbtcp_trafficgen
      EXPORT proxygen-exports
      DESTINATION bin
  )
  add_executable(stress_mvfst
      samples/stress_mvfst/main.cpp
      samples/stress_mvfst/StressMvfst.cpp
      samples/stress_mvfst/FizzContext.cpp
      samples/stress_mvfst/HQParams.cpp
      samples/stress_mvfst/TGConnection.cpp
      samples/stress_mvfst/GETHandler.cpp
  )
  target_compile_options(
      stress_mvfst
      PRIVATE
          ${_PROXYGEN_COMMON_COMPILE_OPTIONS}
  )
  target_link_libraries(
      stress_mvfst
      PUBLIC
          proxygen
          proxygencurl
          mvfst::mvfst_transport
          mvfst::mvfst_client
  )
  install(
      TARGETS stress_mvfst
      EXPORT proxygen-exports
      DESTINATION bin
  )
endif()

file(
    GLOB_RECURSE PROXYGEN_HTTPSERVER_HEADERS_TOINSTALL
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    *.h
)
list(FILTER PROXYGEN_HTTPSERVER_HEADERS_TOINSTALL EXCLUDE REGEX tests/)
list(FILTER PROXYGEN_HTTPSERVER_HEADERS_TOINSTALL EXCLUDE REGEX Mocks.h)
list(FILTER PROXYGEN_HTTPSERVER_HEADERS_TOINSTALL EXCLUDE REGEX samples/)
foreach(header ${PROXYGEN_HTTPSERVER_HEADERS_TOINSTALL})
    get_filename_component(header_dir ${header} DIRECTORY)
    install(FILES ${header} DESTINATION include/proxygen/httpserver/${header_dir})
endforeach()

add_subdirectory(tests)
add_subdirectory(filters/tests)
#add_subdirectory(samples/echo/test)
