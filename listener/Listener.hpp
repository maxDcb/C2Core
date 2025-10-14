#pragma once

#include <chrono>
#include <queue>
#include <mutex>
#include <vector>

#include <CommonCommand.hpp>
#include <Session.hpp>
#include <Common.hpp>
#include <nlohmann/json.hpp>

#ifdef BUILD_TEAMSERVER
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/basic_file_sink.h"
#endif

class Listener
{

public:
    Listener(const std::string& param1, const std::string& param2, const std::string& type);
    virtual ~Listener(){};

        const std::string & getParam1() const;
        const std::string & getParam2() const;
        const std::string & getType() const;
        const std::string & getListenerHash() const;
        const std::string & getListenerMetadata() const
        {
                return m_metadata;
        }
        std::size_t getNumberOfSession() const;

    // Session
    std::shared_ptr<Session> getSessionPtr(int idxSession);
        std::shared_ptr<Session> getSessionPtr(const std::string& beaconHash, const std::string& listenerHash);
        bool isSessionExist(const std::string& beaconHash, const std::string& listenerHash);
        bool updateSessionProofOfLife(const std::string& beaconHash, std::string& lastProofOfLife);
        bool markSessionKilled(const std::string& beaconhash);

    // Session Listener
    bool addSessionListener(const std::string& beaconHash, const std::string& listenerHash, const std::string& type, const std::string& param1, const std::string& param2);
    bool rmSessionListener(const std::string& beaconHash, const std::string& listenerHash);
    std::vector<SessionListener> getSessionListenerInfos();

    // Task & Task Result
    void queueTask(const std::string& beaconHash, const C2Message& c2Message);
    bool addTask(const C2Message& task, const std::string& beaconHash);
        C2Message getTask(const std::string& beaconHash);
        bool addTaskResult(const C2Message& taskResult, const std::string& beaconHash);
        C2Message getTaskResult(const std::string& beaconHash);

    // SocksSession
        bool isSocksSessionExist(const std::string& beaconHash, const std::string& listenerHash);
        bool addSocksTaskResult(const C2Message& taskResult, const std::string& beaconHash);
    C2Message getSocksTaskResult(const std::string& beaconHash);

    // set the listener as primary (meaning launch from the teamserver)
    void setIsPrimary()
    {
        m_isPrimary=true;
    }

protected:
        bool execInstruction(std::vector<std::string>& splitedCmd, C2Message& c2Message);
        bool handleMessages(const std::string& input, std::string& output);

        std::string m_key;
    std::string m_param1;
    std::string m_param2;
    std::string m_type;
    bool m_isPrimary;

    std::string m_listenerHash;
    std::string m_hostname;

    std::string m_metadata;

    std::vector<std::shared_ptr<Session>> m_sessions;
    std::vector<std::shared_ptr<SocksSession>> m_socksSessions;

#ifdef BUILD_TEAMSERVER
        std::shared_ptr<spdlog::logger> m_logger;
        static spdlog::level::level_enum resolveLogLevel(const nlohmann::json& globalConfig,
                                                         const nlohmann::json* listenerConfig = nullptr,
                                                         spdlog::level::level_enum fallback = spdlog::level::info);
#endif

private:
    std::mutex m_mutex;    
};
