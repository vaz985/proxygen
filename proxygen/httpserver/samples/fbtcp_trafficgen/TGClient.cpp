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
#include <proxygen/httpserver/samples/fbtcp_trafficgen/TGClient.h>
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

TGClient::TGClient(const HQParams params,
                   folly::EventBase* evb,
                   const proxygen::URL& requestUrl)
    : params_(params), evb_(evb), firstRequest(requestUrl) {
  if (params_.transportSettings.pacingEnabled) {
    pacingTimer_ = TimerHighRes::newTimer(
        evb_, params_.transportSettings.pacingTimerTickInterval);
  }
}

void TGClient::start() {
  if (connState_ != ConnCallbackState::NONE) {
    LOG(ERROR) << "Maybe we are requesting too fast after creating a new connection";
    return;
  }
  connState_ = ConnCallbackState::STARTING;

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

  std::string localAddress = "";
  if (params_.localAddress) {
    localAddress = params_.localAddress.value().describe();
  }

  session_->startNow();
  quicClient_->start(session_);
}

void TGClient::close() {
  if (connState_ == ConnCallbackState::NONE) {
    LOG(ERROR) << "TODO: Check if this is problematic";
  } else {
    session_->drain();
    session_->closeWhenIdle();
  }
  connState_ = ConnCallbackState::DONE;
}

void TGClient::connectSuccess() {
  connState_ = ConnCallbackState::CONNECT_SUCCESS;
  VLOG(1) << "connectSuccess";
  sendRequest(firstRequest);
}

void TGClient::onReplaySafe() {
  connState_ = ConnCallbackState::REPLAY_SAFE;
  VLOG(1) << "Transport replay safe";
}

void TGClient::connectError(std::pair<quic::QuicErrorCode, std::string> error) {
  connState_ = ConnCallbackState::DONE;
  LOG(ERROR) << "TGClient failed to connect, error=" << toString(error.first)
             << ", msg=" << error.second;
}

static std::function<void()> selfSchedulingRequestRunner;

proxygen::HTTPTransaction* FOLLY_NULLABLE
TGClient::sendRequest(const proxygen::URL& requestUrl) {
  if (connState_ == ConnCallbackState::DONE) {
    return nullptr;
  }
  if (connState_ == ConnCallbackState::NONE) {
    return nullptr;
  }
  if (!createdStreams.empty() && !createdStreams.back()->ended()) {
    return nullptr;
  }

  std::unique_ptr<ConnHandler> client =
      std::make_unique<ConnHandler>(evb_,
                                    params_.httpMethod,
                                    requestUrl,
                                    nullptr,
                                    params_.httpHeaders,
                                    params_.httpBody,
                                    false,
                                    params_.httpVersion.major,
                                    params_.httpVersion.minor);
  if (cb_) {
    client->setCallback(cb_.value());
  }

  client->setLogging(false);
  auto txn = session_->newTransaction(client.get());
  if (!txn) {
    return nullptr;
  }
  client->sendRequest(txn);
  // The emplace guarantees that no other stream will be created before rcving
  // EOM, maybe we should guarantee this earlier
  createdStreams.emplace_back(std::move(client));
  return txn;
}

void TGClient::initializeQuicClient() {
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

}} // namespace quic::samples
