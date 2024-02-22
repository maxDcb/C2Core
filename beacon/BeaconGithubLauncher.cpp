#include "BeaconGithub.hpp"


using namespace std;


int main(int argc, char* argv[])
{	
	std::string project = "";
	if(argc > 1)
		project = argv[1];

	std::string token = "";
	if (argc > 2)
		token = argv[2];

	std::unique_ptr<Beacon> beacon;
	beacon = make_unique<BeaconGithub>(project, token);

	bool exit = false;
	while (!exit)
	{
		try 
		{
			beacon->checkIn();

			exit = beacon->runTasks();
			
			beacon->sleep();
		}
		catch(const std::exception& ex)
		{
			std::cout << "Exeption " << ex.what() << std::endl;
			beacon->sleep();
		}
		catch (...) 
		{
			std::cout << "Exeption" << std::endl;
			beacon->sleep();
		}
	}

	beacon->checkIn();
}