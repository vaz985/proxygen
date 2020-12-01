#pragma once

#include <chrono>
#include <random>
#include <string>

#include <folly/File.h>

#include <proxygen/lib/utils/URL.h>

namespace quic { namespace samples {

using Clock = std::chrono::high_resolution_clock;
using TimePoint = std::chrono::time_point<Clock>;

static std::random_device rd;
static std::mt19937 gen(rd());

// TODO: Make a enum for the gen type
struct TrafficComponent {
  TimePoint nextEvent;
  std::string name_;
  double rate_;
  proxygen::URL url_;
  std::exponential_distribution<double> distrib;

  TrafficComponent(std::string name, double rate) : name_(name), rate_(rate) {
    url_ = proxygen::URL(name_);
    distrib = std::exponential_distribution<>(rate_);
    nextEvent = Clock::now();
    updateEvent();
  }

  bool operator<(const TrafficComponent& rhs) const {
    return nextEvent > rhs.nextEvent;
  }

  void updateEvent() {
    nextEvent += std::chrono::milliseconds(int(1000 * distrib(gen)));
  }
};

void writeToOutput(folly::Optional<folly::File>& outputFileOpt,
                   const std::string& line);

}} // namespace quic::samples