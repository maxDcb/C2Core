#pragma once

#include <cstdint>
#include <string>

class SocksTunnelClient {
public:
  explicit SocksTunnelClient(int id = 0) : m_id(id) {}
  int init(std::uint32_t, std::uint16_t) { return 1; }
  int process(const std::string&, std::string&) { return -1; }
  int getId() const { return m_id; }
  void reset() {}
private:
  int m_id;
};
