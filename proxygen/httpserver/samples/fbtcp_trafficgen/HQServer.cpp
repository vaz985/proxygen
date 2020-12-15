/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQServer.h>

#include <ostream>
#include <string>
#include <sys/stat.h>

#include <boost/algorithm/string.hpp>

#include <folly/io/async/EventBaseManager.h>

#include <proxygen/httpserver/HTTPServer.h>
#include <proxygen/httpserver/HTTPTransactionHandlerAdaptor.h>
#include <proxygen/httpserver/RequestHandlerFactory.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/FizzContext.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQLoggerHelper.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/HQParams.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/SampleHandlers.h>
#include <proxygen/httpserver/samples/fbtcp_trafficgen/Utils.h>
#include <proxygen/lib/http/session/HQDownstreamSession.h>
#include <proxygen/lib/http/session/HTTPSessionController.h>
#include <proxygen/lib/utils/WheelTimerInstance.h>

#include <quic/congestion_control/ServerCongestionControllerFactory.h>
#include <quic/logging/FileQLogger.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>

namespace quic { namespace samples {
using fizz::server::FizzServerContext;
using proxygen::HQDownstreamSession;
using proxygen::HQSession;
using proxygen::HTTPException;
using proxygen::HTTPMessage;
using proxygen::HTTPSessionBase;
using proxygen::HTTPTransaction;
using proxygen::HTTPTransactionHandler;
using proxygen::HTTPTransactionHandlerAdaptor;
using proxygen::RequestHandler;
using quic::QuicServerTransport;
using quic::QuicSocket;

static std::atomic<bool> shouldPassHealthChecks{true};

inline bool fileExist(const std::string& name) {
  struct stat buffer;
  return (stat(name.c_str(), &buffer) == 0);
}

HTTPTransactionHandler* Dispatcher::getRequestHandler(HTTPMessage* msg,
                                                      const HQParams& params) {
  DCHECK(msg);
  auto path = msg->getPathAsStringPiece();
  // If we have static folder on, we check if the file exists. Otherwise we
  // assume that the client wants the RandBytesGen
  if (!params.staticRoot.empty()) {
    auto filePath = folly::to<std::string>(params.staticRoot, "/", path);
    if (fileExist(filePath)) {
      return new StaticFileHandler(params);
    }
  }
  if (path.size() > 1 && path[0] == '/' && std::isdigit(path[1])) {
    return new RandBytesGenHandler(params);
  }
  return new DummyHandler(params);
}

void outputQLog(const HQParams& params) {
}

HQSessionController::HQSessionController(
    const HQParams& params,
    const HTTPTransactionHandlerProvider& httpTransactionHandlerProvider)
    : params_(params),
      httpTransactionHandlerProvider_(httpTransactionHandlerProvider) {
}

HQSession* HQSessionController::createSession() {
  wangle::TransportInfo tinfo;
  session_ = new HQDownstreamSession(params_.txnTimeout, this, tinfo, this);
  return session_;
}

void HQSessionController::startSession(std::shared_ptr<QuicSocket> sock) {
  CHECK(session_);
  session_->setSocket(std::move(sock));
  session_->startNow();
}

void HQSessionController::onTransportReady(HTTPSessionBase* /*session*/) {
  if (params_.sendKnobFrame) {
    sendKnobFrame("Hello, World from Server!");
  }
}

void HQSessionController::onDestroy(const HTTPSessionBase&) {
}

void HQSessionController::sendKnobFrame(const folly::StringPiece str) {
  if (str.empty()) {
    return;
  }
  uint64_t knobSpace = 0xfaceb00c;
  uint64_t knobId = 200;
  Buf buf(folly::IOBuf::create(str.size()));
  memcpy(buf->writableData(), str.data(), str.size());
  buf->append(str.size());
  VLOG(10) << "Sending Knob Frame to peer. KnobSpace: " << std::hex << knobSpace
           << " KnobId: " << std::dec << knobId << " Knob Blob" << str;
  const auto knobSent = session_->sendKnob(0xfaceb00c, 200, std::move(buf));
  if (knobSent.hasError()) {
    LOG(ERROR) << "Failed to send Knob frame to peer. Received error: "
               << knobSent.error();
  }
}

HTTPTransactionHandler* HQSessionController::getRequestHandler(
    HTTPTransaction& /*txn*/, HTTPMessage* msg) {
  return httpTransactionHandlerProvider_(msg, params_);
}

HTTPTransactionHandler* FOLLY_NULLABLE
HQSessionController::getParseErrorHandler(
    HTTPTransaction* /*txn*/,
    const HTTPException& /*error*/,
    const folly::SocketAddress& /*localAddress*/) {
  return nullptr;
}

HTTPTransactionHandler* FOLLY_NULLABLE
HQSessionController::getTransactionTimeoutHandler(
    HTTPTransaction* /*txn*/, const folly::SocketAddress& /*localAddress*/) {
  return nullptr;
}

void HQSessionController::attachSession(HTTPSessionBase* /*session*/) {
}

void HQSessionController::detachSession(const HTTPSessionBase* /*session*/) {
  delete this;
}

HQServerTransportFactory::HQServerTransportFactory(
    const HQParams& params,
    const HTTPTransactionHandlerProvider& httpTransactionHandlerProvider)
    : params_(params),
      httpTransactionHandlerProvider_(httpTransactionHandlerProvider),
      samplingRate_(0.0, 1.0) {
  if (params_.eventLogs.size() > 0) {
    std::string logPath = params_.eventLogs + "/event.log";
    auto fp =
        folly::File::makeFile(logPath, O_WRONLY | O_TRUNC | O_CREAT).value();
    obs_.emplace(std::move(fp));
  }
}

QuicServerTransport::Ptr HQServerTransportFactory::make(
    folly::EventBase* evb,
    std::unique_ptr<folly::AsyncUDPSocket> socket,
    const folly::SocketAddress& /* peerAddr */,
    std::shared_ptr<const FizzServerContext> ctx) noexcept {
  // Session controller is self owning
  auto hqSessionController =
      new HQSessionController(params_, httpTransactionHandlerProvider_);
  auto session = hqSessionController->createSession();
  CHECK_EQ(evb, socket->getEventBase());
  auto transport =
      QuicServerTransport::make(evb, std::move(socket), *session, ctx);

  // Add sampling rate here?
  if (obs_ && (samplingRate_(gen) <= params_.samplingRate)) {
    transport->addInstrumentationObserver(obs_.get_pointer());
  }

  if (!params_.qLoggerPath.empty()) {
    transport->setQLogger(std::make_shared<HQLoggerHelper>(
        params_.qLoggerPath, params_.prettyJson, quic::VantagePoint::Server));
  }
  hqSessionController->startSession(transport);
  return transport;
}

HQServer::HQServer(
    const HQParams& params,
    HTTPTransactionHandlerProvider httpTransactionHandlerProvider)
    : params_(params), server_(quic::QuicServer::createQuicServer()) {
  server_->setBindV6Only(false);
  server_->setCongestionControllerFactory(
      std::make_shared<ServerCongestionControllerFactory>());
  server_->setTransportSettings(params_.transportSettings);
  server_->setCcpConfig(params_.ccpConfig);

  server_->setQuicServerTransportFactory(
      std::make_unique<HQServerTransportFactory>(
          params_, std::move(httpTransactionHandlerProvider)));

  server_->setQuicUDPSocketFactory(
      std::make_unique<QuicSharedUDPSocketFactory>());
  server_->setHealthCheckToken("health");
  server_->setSupportedVersion(params_.quicVersions);
  server_->setFizzContext(createFizzServerContext(params_));
  if (params_.rateLimitPerThread) {
    server_->setRateLimit(params_.rateLimitPerThread.value(), 1s);
  }
}

void HQServer::setTlsSettings(const HQParams& params) {
  server_->setFizzContext(createFizzServerContext(params));
}

void HQServer::start() {
  server_->start(params_.localAddress.value(), params_.numWorkers);
}

void HQServer::run() {
  eventbase_.loopForever();
}

const folly::SocketAddress HQServer::getAddress() const {
  server_->waitUntilInitialized();
  const auto& boundAddr = server_->getAddress();
  LOG(INFO) << "HQ server started at: " << boundAddr.describe();
  LOG(INFO) << "Sampling rate: " << params_.samplingRate * 100 << "%";
  return boundAddr;
}

void HQServer::stop() {
  server_->shutdown();
  eventbase_.terminateLoopSoon();
}

void HQServer::rejectNewConnections(bool reject) {
  server_->rejectNewConnections(reject);
}

H2Server::SampleHandlerFactory::SampleHandlerFactory(
    const HQParams& params,
    HTTPTransactionHandlerProvider httpTransactionHandlerProvider)
    : params_(params),
      httpTransactionHandlerProvider_(
          std::move(httpTransactionHandlerProvider)) {
}

void H2Server::SampleHandlerFactory::onServerStart(
    folly::EventBase* /*evb*/) noexcept {
}

void H2Server::SampleHandlerFactory::onServerStop() noexcept {
}

RequestHandler* H2Server::SampleHandlerFactory::onRequest(
    RequestHandler*, HTTPMessage* msg) noexcept {
  return new HTTPTransactionHandlerAdaptor(
      httpTransactionHandlerProvider_(msg, params_));
}

std::unique_ptr<proxygen::HTTPServerOptions> H2Server::createServerOptions(
    const HQParams& params,
    HTTPTransactionHandlerProvider httpTransactionHandlerProvider) {
  auto serverOptions = std::make_unique<proxygen::HTTPServerOptions>();

  serverOptions->threads = params.httpServerThreads;
  serverOptions->idleTimeout = params.httpServerIdleTimeout;
  serverOptions->shutdownOn = params.httpServerShutdownOn;
  serverOptions->enableContentCompression =
      params.httpServerEnableContentCompression;
  serverOptions->initialReceiveWindow =
      params.transportSettings.advertisedInitialBidiLocalStreamWindowSize;
  serverOptions->receiveStreamWindowSize =
      params.transportSettings.advertisedInitialBidiLocalStreamWindowSize;
  serverOptions->receiveSessionWindowSize =
      params.transportSettings.advertisedInitialConnectionWindowSize;
  serverOptions->handlerFactories =
      proxygen::RequestHandlerChain()
          .addThen<SampleHandlerFactory>(
              params, std::move(httpTransactionHandlerProvider))
          .build();
  return serverOptions;
}

std::unique_ptr<H2Server::AcceptorConfig> H2Server::createServerAcceptorConfig(
    const HQParams& params) {
  auto acceptorConfig = std::make_unique<AcceptorConfig>();
  proxygen::HTTPServer::IPConfig ipConfig(
      params.localH2Address.value(), proxygen::HTTPServer::Protocol::HTTP2);
  ipConfig.sslConfigs.emplace_back(createSSLContext(params));
  acceptorConfig->push_back(ipConfig);
  return acceptorConfig;
}

std::thread H2Server::run(
    const HQParams& params,
    HTTPTransactionHandlerProvider httpTransactionHandlerProvider) {

  // Start HTTPServer mainloop in a separate thread
  std::thread t([params = folly::copy(params),
                 httpTransactionHandlerProvider =
                     std::move(httpTransactionHandlerProvider)]() mutable {
    {
      auto acceptorConfig = createServerAcceptorConfig(params);
      auto serverOptions = createServerOptions(
          params, std::move(httpTransactionHandlerProvider));
      proxygen::HTTPServer server(std::move(*serverOptions));
      server.bind(std::move(*acceptorConfig));
      server.start();
    }
    // HTTPServer traps the SIGINT.  resignal HQServer
    raise(SIGINT);
  });

  return t;
}

void startServer(const HQParams& params) {
  // Run H2 server in a separate thread
  // auto h2server = H2Server::run(params, Dispatcher::getRequestHandler);
  // Run HQ server
  HQServer server(params, Dispatcher::getRequestHandler);
  server.start();
  // Wait until the quic server initializes
  server.getAddress();
  // Start HQ sever event loop
  server.run();
  // h2server.join();
}

// Observer
ConnectionObserver::ConnectionObserver(
    folly::Optional<folly::File>&& outputFile)
    : outputFile_(std::move(outputFile)) {
  std::vector<std::string> row;
  row.push_back("evtstamp");
  row.push_back("type");
  row.push_back("dst");
  row.push_back("src");
  row.push_back("sample_rtt_ms");
  row.push_back("sample_ackdelay_ms");
  const std::lock_guard<std::mutex> lock(writeMutex);
  writeToOutput(outputFile_, folly::join(",", row));
}

void ConnectionObserver::observerDetach(QuicSocket* sock) noexcept {
}

void ConnectionObserver::rttSampleGenerated(
    QuicSocket* sock, const quic::InstrumentationObserver::PacketRTT& pktRTT) {

  const folly::SocketAddress peerAddress = sock->getPeerAddress();
  const folly::SocketAddress localAddress = sock->getLocalAddress();
  // quic::QuicSocket::TransportInfo tinfo = sock->getTransportInfo();

  std::string dst =
      peerAddress.getAddressStr() + ":" + std::to_string(peerAddress.getPort());
  std::string src = localAddress.getAddressStr() + ":" +
                    std::to_string(localAddress.getPort());

  std::chrono::system_clock::time_point tp = std::chrono::system_clock::now();
  std::chrono::system_clock::duration dtn = tp.time_since_epoch();

  std::vector<std::string> row;
  row.push_back(std::to_string(dtn.count()));
  row.push_back("RTTEVENT");
  row.push_back(dst);
  row.push_back(src);
  row.push_back(std::to_string(pktRTT.rttSample.count()));
  row.push_back(std::to_string(pktRTT.ackDelay.count()));

  const std::lock_guard<std::mutex> lock(writeMutex);
  writeToOutput(outputFile_, folly::join(",", row));
}

void ConnectionObserver::packetLossDetected(
    QuicSocket* sock,
    const struct quic::InstrumentationObserver::ObserverLossEvent& lossEvent) {

  const folly::SocketAddress peerAddress = sock->getPeerAddress();
  const folly::SocketAddress localAddress = sock->getLocalAddress();

  std::string dst =
      peerAddress.getAddressStr() + ":" + std::to_string(peerAddress.getPort());
  std::string src = localAddress.getAddressStr() + ":" +
                    std::to_string(localAddress.getPort());

  std::vector<std::string> lostPackets;
  for (auto it : lossEvent.lostPackets) {
    lostPackets.emplace_back(
        std::to_string(it.packet.packet.header.getPacketSequenceNum()));
  }
}

}} // namespace quic::samples
