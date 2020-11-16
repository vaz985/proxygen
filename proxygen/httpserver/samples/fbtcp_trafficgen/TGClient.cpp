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

TGClient::TGClient(const HQParams params, folly::EventBase* evb)
    : params_(params), evb_(evb) {
  if (params_.transportSettings.pacingEnabled) {
    pacingTimer_ = TimerHighRes::newTimer(
        evb_, params_.transportSettings.pacingTimerTickInterval);
  }
}

void TGClient::start(const proxygen::URL requestUrl) {
  firstRequest = requestUrl;

  initializeQuicClient();

  wangle::TransportInfo tinfo;
  session_ = new proxygen::HQUpstreamSession(params_.txnTimeout,
                                             params_.connectTimeout,
                                             nullptr, // controller
                                             tinfo,
                                             nullptr); // codecfiltercallback

  // Need this for Interop since we use HTTP0.9
  session_->setForceUpstream1_1(false);

  // TODO: this could now be moved back in the ctor
  session_->setSocket(quicClient_);
  session_->setConnectCallback(this);

  LOG(INFO) << "[CID " << params_.cid << "] Connecting to "
            << params_.remoteAddress->describe();
  session_->startNow();
  quicClient_->start(session_);
}

void TGClient::connectSuccess() {
  sendRequest(firstRequest);

  session_->drain();
  session_->closeWhenIdle();
}

void TGClient::onReplaySafe() {
  VLOG(10) << "Transport replay safe";
}

void TGClient::connectError(std::pair<quic::QuicErrorCode, std::string> error) {
  LOG(ERROR) << "TGClient failed to connect, error=" << toString(error.first)
             << ", msg=" << error.second;
}

proxygen::HTTPTransaction* FOLLY_NULLABLE
TGClient::sendRequest(const proxygen::URL requestUrl) {
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

  client->setLogging(params_.logResponse);
  auto txn = session_->newTransaction(client.get());
  if (!txn) {
    return nullptr;
  }
  client->saveResponseToNull();
  client->sendRequest(txn);
  curls_.emplace_back(std::move(client));
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
