#pragma once

#include "Beacon.hpp"
#include "../TcpFrameBuffer.hpp"

class SocketTunnelClient;


class BeaconTcp : public Beacon
{

public:
    BeaconTcp(std::string& config, std::string& ip, int port);
    ~BeaconTcp();

private:
    std::string m_ip;
    int m_port;

    void checkIn();

    SocketTunnelClient* m_client;
    TcpFrameBuffer m_frames;
};
