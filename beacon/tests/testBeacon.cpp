#include "Beacon.hpp"


class BeaconTester : public Beacon
{

public:
	BeaconTester()
    : Beacon("127.0.0.1", 666)
    {

    }

	~BeaconTester()
    {

    }

    void checkIn()
    {	
    }

	void cmdToTasksTest(const std::string& input)
    {	
        cmdToTasks(input);
    }

    void taskResultsToCmdTest(std::string& output)
    {	
        taskResultsToCmd(output);
    }

    void execInstructionTest(std::string& output)
    {	
        // execInstruction();
    }

    

};



int main()
{
    //
    // Constructor tests
    //
    {
        BeaconTester beacon;
    }

    //
    // cmdToTasksTest tests
    //
    {
        BeaconTester beacon;

        std::string input = "test string to take";
        beacon.cmdToTasksTest(input);
    }
    {
        BeaconTester beacon;

        std::string data = "test string to take";
        std::string input = base64_encode(data);
        beacon.cmdToTasksTest(input);
    }

    //
    // runTasks tests
    //

    //
    // taskResultsToCmd tests
    //

    //
    // execInstruction tests
    //

    //
    // sleep tests
    //
}