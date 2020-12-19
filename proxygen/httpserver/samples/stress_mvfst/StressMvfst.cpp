#include <vector>

#include <proxygen/httpserver/samples/stress_mvfst/StressMvfst.h>
#include <proxygen/httpserver/samples/stress_mvfst/TGConnection.h>

namespace quic { namespace samples {

void StressMvfst::start() {
  LOG(INFO) << "start()";
  // for (uint32_t i = 0; i < numWorkers; ++i) {
  //   std::string evbName = "Worker " + std::to_string(i);
  //   auto scopedEvb = std::make_unique<folly::ScopedEventBaseThread>();
  //   workerEvbs_.push_back(std::move(scopedEvb));
  //   auto workerEvb = workerEvbs_.back()->getEventBase();
  //   workerEvb->terminateLoopSoon();
  //   workerEvb->setName(evbName);
  //   evbs.push_back(workerEvb);
  // }
  for (uint32_t i = 0; i < numWorkers; ++i) {
    folly::EventBase* evb = new folly::EventBase;
    evbs.push_back(evb);
  }
  CHECK(evbs.size() == numWorkers);

  std::vector<std::shared_ptr<TGConnection>> createdConnections;
  for (uint32_t i = 0; i < numClients; i++) {
    auto conn = std::make_shared<TGConnection>(params_, evbs[i % numWorkers]);
    createdConnections.push_back(std::move(conn));
    evbs[i % numWorkers]->runInEventBaseThreadAlwaysEnqueue([&, i]() {
      LOG(INFO) << "Running request " << i;
      createdConnections[i]->start();
      // createdConnections[i]->sendRequest("/32k.bin");
      // createdConnections[i]->startClosing();
    });
  }

  for (uint32_t i = 0; i < numWorkers; ++i) {
    evbsThreads.push_back(std::move(std::thread([&, i]{
      evbs[i]->loopForever();
    })));
  }
  
  int timeRem = 20;
  while (timeRem-- > 0) {
    uint32_t connected = 0;
    for (auto conn : createdConnections) {
      connected += conn->connected();
    }
    LOG(INFO) << "Connected: " << connected << "/" << createdConnections.size(); 
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  std::vector<std::string> successfulConnections;
  std::vector<std::string> failedConnections;
  // for (auto conn : crea)
}

}}