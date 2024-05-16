#include "ListenerTcp.hpp"


using namespace std;


ListenerTcp::ListenerTcp(const std::string& ip, int localPort)
	: Listener("0.0.0.0", std::to_string(localPort), ListenerTcpType)
{
#ifdef __linux__

	bool isPortInUse = port_in_use(localPort);
	if(isPortInUse)
		throw std::runtime_error("Port Already Used.");
		
#elif _WIN32
#endif


	m_listenerHash = random_string(SizeListenerHash);
	m_listenerHash += '\x60';
	m_listenerHash += ListenerTcpType;
	m_listenerHash += '\x60';
	m_listenerHash += m_hostname;
	m_listenerHash += "->";
	m_listenerHash += ip;
	m_listenerHash += '\x60';
	m_listenerHash += std::to_string(localPort);

	m_port = localPort;

	m_serverTcp = new SocketHandler::Server(m_port);

	m_stopThread=false;
	m_tcpServ = std::make_unique<std::thread>(&ListenerTcp::lauchTcpServ, this);
}


ListenerTcp::~ListenerTcp()
{
	m_stopThread=true;
	m_tcpServ->join();

	delete m_serverTcp;
}


void ListenerTcp::lauchTcpServ()
{
	try 
    {
		while(1)
		{
			if(m_stopThread)
				return;

			m_serverTcp->initServer();

			SPDLOG_DEBUG("receiving");
	
			string input;
			bool res = m_serverTcp->receive(input);

			SPDLOG_DEBUG("received input.size {0}", std::to_string(input.size()));

			if(res && !input.empty())
			{
				string output;
				bool ret = handleMessages(input, output);

				SPDLOG_DEBUG("sending output.size {0}", std::to_string(output.size()));

				res = m_serverTcp->sendData(output);	
				if(res)
				{
					SPDLOG_DEBUG("sent");
				}
			}

			m_serverTcp->closeConnection();
			
			std::this_thread::sleep_for(std::chrono::milliseconds(200));
		}
	}
    catch (...)
    {
        return;
    }

	return;
}

