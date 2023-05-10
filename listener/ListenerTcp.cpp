#include "ListenerTcp.hpp"


using namespace std;


ListenerTcp::ListenerTcp(const std::string& ip, int localPort)
	: Listener(ip, localPort, ListenerTcpType)
{
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

			DEBUG("receiving");
	
			string input;
			bool res = m_serverTcp->receive(input);

			DEBUG("received input.size " << std::to_string(input.size()));

			if(res && !input.empty())
			{
				string output;
				bool ret = handleMessages(input, output);

				if (output.empty())
					output = "{}";

				DEBUG("sending output.size " << std::to_string(output.size()));

				res = m_serverTcp->sendData(output);	
				if(res)
				{
					DEBUG("sent");
				}
			}

			std::this_thread::sleep_for(std::chrono::milliseconds(200));
		}
	}
    catch (...)
    {
        return;
    }

	return;
}

