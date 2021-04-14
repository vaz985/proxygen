# Copyright (c) Facebook, Inc. and its affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

if (BUILD_QUIC)
    add_executable(fbtcp_trafficgen
        main.cpp
        FizzContext.cpp
        HQLoggerHelper.cpp
        HQParams.cpp
        HQServer.cpp
        SampleHandlers.cpp
        TrafficGenerator.cpp
        TGConnection.cpp
        GETHandler.cpp
        Utils.cpp
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
endif()