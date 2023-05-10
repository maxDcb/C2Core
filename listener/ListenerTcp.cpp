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

			DEBUG("receiving");
	
			string input;
			m_serverTcp->receive(input);

			DEBUG("received input.size " << std::to_string(input.size()));

			if(input.size()!=0)
			{
				string output;
				bool ret = handleMessages(input, output);

				// No matter if output is empty we need to respond in TCP
				// we send one byte for the compatiblity windows/linux SocketHandler
				if (output.empty())
					output = "{}";

				DEBUG("sending output.size " << std::to_string(output.size()));

				m_serverTcp->sendData(output);	

				DEBUG("sent");
			}

			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}
	}
    catch (...)
    {
        return;
    }

	return;
}

