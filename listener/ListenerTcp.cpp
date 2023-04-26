#include "ListenerTcp.hpp"


using namespace std;
using namespace SocketHandler;


ListenerTcp::ListenerTcp(const std::string& ip, int localPort)
	: Listener(ip, localPort, ListenerTcpType)
{
	Server* server_ = new Server(m_port);
	m_serversTcp.push_back(std::move(server_));

	m_stopThread=false;
	m_tcpServ = std::make_unique<std::thread>(&ListenerTcp::lauchTcpServ, this);
}


ListenerTcp::~ListenerTcp()
{
	m_stopThread=true;
	m_tcpServ->join();

	for (int i = 0; i < m_serversTcp.size(); i++)
		if (m_serversTcp[i])
			delete m_serversTcp[i];
}


void ListenerTcp::lauchTcpServ()
{
	try 
    {
		while(1)
		{
			if(m_stopThread)
				return;

			string input;
			m_serversTcp[0]->receive(input);

			string output;
			bool ret = handleMessages(input, output);

			// No matter if output is empty we need to respond in TCP
			// we send one byte for the compatiblity windows/linux SocketHandler
			if (output.empty())
				output = ".";
			m_serversTcp[0]->sendData(output);	

			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}
	}
    catch (...)
    {
        return;
    }

	return;
}

