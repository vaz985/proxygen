/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <fstream>
#include <ostream>
#include <string>
#include <thread>

#include <folly/io/async/AsyncTimeout.h>
#include <folly/io/async/EventBaseManager.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <folly/json.h>

#include <proxygen/httpserver/samples/fbtcp_trafficgen/FizzContext.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQLoggerHelper.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/InsecureVerifierDangerousDoNotUseInProduction.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/TGConnection.h>
#include <proxygen/lib/http/codec/HTTP1xCodec.h>
#include <proxygen/lib/utils/UtilInl.h>

#include <quic/api/QuicSocket.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>

namespace quic { namespace samples {

// static std::string getTargetAddr(const uint32_t gid) {
//   // Not safe
//   char buffer[255];
//   int n = sprintf(buffer, "10.255.%d.2", gid);
//   CHECK(n < 10);
//   return std::string(buffer);
// }

TGConnection::TGConnection(const HQParams params, folly::EventBase* evb)
    : params_(params), evb_(evb) {
  if (params_.transportSettings.pacingEnabled) {
    pacingTimer_ = TimerHighRes::newTimer(
        evb_, params_.transportSettings.pacingTimerTickInterval);
  }
}

void TGConnection::start() {
  if (connState_ != ConnectionState::NONE) {
    // LOG(ERROR)
    //     << "Maybe we are requesting too fast after creating a new
    //     connection";
    return;
  }

  initializeQuicClient();

  wangle::TransportInfo tinfo;
  session_ = new proxygen::HQUpstreamSession(params_.txnTimeout,
                                             params_.connectTimeout,
                                             nullptr, // controller
                                             tinfo,
                                             nullptr); // codecfiltercallback

  // TODO: this could now be moved back in the ctor
  session_->setSocket(quicClient_);
  session_->setConnectCallback(this);

  session_->startNow();
  quicClient_->start(session_);
}

void TGConnection::connectSuccess() {
  connState_ = ConnectionState::CONNECT_SUCCESS;
  // LOG(INFO) << "Connection successful on " <<
  // session_->getLocalAddress().describe();
  if (nextRequest) {
    nextRequest.value()();
    nextRequest.clear();
  }
}

void TGConnection::onReplaySafe() {
  connState_ = ConnectionState::REPLAY_SAFE;
  VLOG(1) << "Transport replay safe";
  if (nextRequest) {
    nextRequest.value()();
    nextRequest.clear();
  }
}

void TGConnection::connectError(
    std::pair<quic::QuicErrorCode, std::string> error) {
  connState_ = ConnectionState::DONE;
  // LOG(ERROR) << "TGConnection failed to connect, error="
  //            << toString(error.first) << ", msg=" << error.second;
}

proxygen::HTTPTransaction* FOLLY_NULLABLE
TGConnection::sendRequest(std::string requestName) {
  if (connState_ == ConnectionState::DONE) {
    VLOG(1) << "Stopped request, DONE";
    return nullptr;
  }
  // We set the request to run when the connection is established
  if (connState_ == ConnectionState::NONE) {
    VLOG(1) << "Request after connect, queuing first request and now the "
               "connection is pending";
    nextURL = requestName;
    nextRequest = [&]() { sendRequest(nextURL); };
    return nullptr;
  }
  if (!createdRequests.empty() && !createdRequests.back()->requestEnded()) {
    // LOG(INFO) << "Stopped request, last stream still running";
    return nullptr;
  }
  if (!quicClient_->good()) {
    connState_ = ConnectionState::DONE;
    // LOG(INFO) << "Stopped request, quicClient not good";
    return nullptr;
  }
  if (quicClient_->error()) {
    connState_ = ConnectionState::DONE;
    // LOG(INFO) << "Stopped request, quicClient error";
    return nullptr;
  }
  // LOG(INFO) << "Running request " << requestUrl.getPath();
  std::unique_ptr<GETHandler> request =
      std::make_unique<GETHandler>(evb_,
                                   params_.httpMethod,
                                   requestName,
                                   nullptr,
                                   params_.httpHeaders,
                                   params_.httpBody,
                                   false,
                                   params_.httpVersion.major,
                                   params_.httpVersion.minor);
  if (cb_) {
    request->setCallback(cb_.value());
  }

  request->setLogging(false);
  auto txn = session_->newTransaction(request.get());
  if (!txn) {
    return nullptr;
  }
  request->sendRequest(txn);
  // The emplace guarantees that no other stream will be created before rcving
  // EOM, maybe we should guarantee this earlier
  createdRequests.emplace_back(std::move(request));
  return txn;
}

void TGConnection::initializeQuicClient() {
  auto sock = std::make_unique<folly::AsyncUDPSocket>(evb_);
  auto client = std::make_shared<quic::QuicClientTransport>(
      evb_,
      std::move(sock),
      quic::FizzClientQuicHandshakeContext::Builder()
          .setFizzClientContext(createFizzClientContext(params_))
          .setCertificateVerifier(
              std::make_unique<
                  proxygen::InsecureVerifierDangerousDoNotUseInProduction>())
          .setPskCache(params_.pskCache)
          .build());
  client->setPacingTimer(pacingTimer_);
  client->setHostname(params_.host);
  client->addNewPeerAddress(params_.remoteAddress.value());
  if (params_.localAddress.has_value()) {
    client->setLocalAddress(*params_.localAddress);
  }
  client->setCongestionControllerFactory(
      std::make_shared<quic::DefaultCongestionControllerFactory>());
  client->setTransportSettings(params_.transportSettings);
  client->setSupportedVersions(params_.quicVersions);

  quicClient_ = std::move(client);
}

void TGConnection::startClosing() {
  connState_ = ConnectionState::DONE;
  close();
}

void TGConnection::close() {
  // QuicTransportBase.cpp:477] close threw exception Cannot encrypt inplace.
  // session_->describe(LOG(INFO) << "Close: ");
  session_->drain();
}

}} // namespace quic::samples
