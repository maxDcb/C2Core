#pragma once

#include <atomic>
#include <chrono>
#include <cmath>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "ModuleCmd.hpp"


class SessionListener
{
public:
        SessionListener(const std::string& listenerHash, const std::string& type, const std::string& param1, const std::string& param2)
        {
            m_listenerHash = listenerHash;
            m_type = type;
            m_param1 = param1;
            m_param2 = param2;
        }

        const std::string& getListenerHash() const
        {
            return m_listenerHash;
        }

        const std::string& getType() const
        {
            return m_type;
        }

        const std::string& getParam1() const
        {
            return m_param1;
        }

        const std::string& getParam2() const
        {
            return m_param2;
        }

private:
    std::string m_listenerHash;
    std::string m_type;
    std::string m_param1;
    std::string m_param2;
};


class Session
{
public:
    static constexpr std::size_t MaxPendingMessages = 4096;
    static constexpr std::size_t MaxChildListeners = 256;

    Session(const std::string& listenerHash, const std::string& beaconHash, const std::string& hostname, const std::string& username,
    const std::string& arch, const std::string& privilege, const std::string& os)
        : m_listenerHash(listenerHash), m_beaconHash(beaconHash), m_hostname(hostname),
          m_username(username), m_arch(arch), m_privilege(privilege), m_os(os),
          m_lastProofOfLife(std::chrono::steady_clock::now()), m_killed(false) {}

    std::string getListenerHash() const { std::lock_guard<std::mutex> lock(m_mutex); return m_listenerHash; }
    std::string getBeaconHash() const { std::lock_guard<std::mutex> lock(m_mutex); return m_beaconHash; }
    std::string getUsername() const { std::lock_guard<std::mutex> lock(m_mutex); return m_username; }
    std::string getHostname() const { std::lock_guard<std::mutex> lock(m_mutex); return m_hostname; }
    std::string getArch() const { std::lock_guard<std::mutex> lock(m_mutex); return m_arch; }
    std::string getPrivilege() const { std::lock_guard<std::mutex> lock(m_mutex); return m_privilege; }
    std::string getOs() const { std::lock_guard<std::mutex> lock(m_mutex); return m_os; }
    std::string getInternalIps() const { std::lock_guard<std::mutex> lock(m_mutex); return m_internalIps; }
    std::string getProcessId() const { std::lock_guard<std::mutex> lock(m_mutex); return m_processId; }
    std::string getAdditionalInformation() const { std::lock_guard<std::mutex> lock(m_mutex); return m_additionalInformation; }

    void setListenerHash(const std::string& value) { std::lock_guard<std::mutex> lock(m_mutex); m_listenerHash = value; }
    void setBeaconHash(const std::string& value) { std::lock_guard<std::mutex> lock(m_mutex); m_beaconHash = value; }
    void setUsername(const std::string& value) { std::lock_guard<std::mutex> lock(m_mutex); m_username = value; }
    void setHostname(const std::string& value) { std::lock_guard<std::mutex> lock(m_mutex); m_hostname = value; }
    void setArch(const std::string& value) { std::lock_guard<std::mutex> lock(m_mutex); m_arch = value; }
    void setPrivilege(const std::string& value) { std::lock_guard<std::mutex> lock(m_mutex); m_privilege = value; }
    void setOs(const std::string& value) { std::lock_guard<std::mutex> lock(m_mutex); m_os = value; }
    void setInternalIps(const std::string& value) { std::lock_guard<std::mutex> lock(m_mutex); m_internalIps = value; }
    void setProcessId(const std::string& value) { std::lock_guard<std::mutex> lock(m_mutex); m_processId = value; }
    void setAdditionalInformation(const std::string& value) { std::lock_guard<std::mutex> lock(m_mutex); m_additionalInformation = value; }

    bool updateProofOfLife(const std::string& value)
    {
        try
        {
            std::size_t parsed = 0;
            const double elapsed = std::stod(value, &parsed);
            if (parsed != value.size() || !std::isfinite(elapsed) || elapsed < 0.0 || elapsed > 31536000.0)
                return false;
            std::lock_guard<std::mutex> lock(m_mutex);
            m_lastProofOfLife = std::chrono::steady_clock::now() -
                std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::duration<double>(elapsed));
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    bool updatePoofOfLife(const std::string& value) { return updateProofOfLife(value); }

    bool isSessionKilled() const
    {
        return m_killed.load();
    }

    void setSessionAlive()
    {
        m_killed=false;
    }

    void setSessionKilled()
    {
        m_killed=true;
    }

    std::string getLastProofOfLife() const
    {
        if(m_killed.load())
            return "-1";
        std::lock_guard<std::mutex> lock(m_mutex);
        return std::to_string(std::chrono::duration<double>(
            std::chrono::steady_clock::now() - m_lastProofOfLife).count());
    }

    int addTask(const C2Message& task)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_messageToSend.size() >= MaxPendingMessages)
            return -1;
        m_messageToSend.push_back(task);
        return static_cast<int>(m_messageToSend.size());
    }

    void prependTask(const C2Message& task)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_messageToSend.size() < MaxPendingMessages)
            m_messageToSend.push_front(task);
    }

    C2Message getTask()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if(!m_messageToSend.empty())
        {
            C2Message output = std::move(m_messageToSend.front());
            m_messageToSend.pop_front();
            return output;
        }
        return C2Message();
    }

    int addTaskResult(const C2Message& taskResult)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::string serialized;
        if (!taskResult.SerializeToString(&serialized))
            return -1;
        const std::string fingerprint = taskResult.uuid() + "\n" + serialized;
        if (m_resultFingerprints.find(fingerprint) != m_resultFingerprints.end())
            return static_cast<int>(m_messageToRead.size());
        if (m_messageToRead.size() >= MaxPendingMessages)
            return -1;
        m_messageToRead.push_back(taskResult);
        m_resultFingerprints.insert(fingerprint);
        m_resultFingerprintOrder.push_back(fingerprint);
        if (m_resultFingerprintOrder.size() > MaxPendingMessages)
        {
            m_resultFingerprints.erase(m_resultFingerprintOrder.front());
            m_resultFingerprintOrder.pop_front();
        }
        return static_cast<int>(m_messageToRead.size());
    }


    C2Message getTaskResult()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_messageToRead.empty())
        {
            C2Message output = std::move(m_messageToRead.front());
            m_messageToRead.pop_front();
            return output;
        }
        return C2Message();
    }

    std::vector<C2Message> drainTaskResults()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<C2Message> results;
        results.reserve(m_messageToRead.size());
        while (!m_messageToRead.empty())
        {
            results.push_back(std::move(m_messageToRead.front()));
            m_messageToRead.pop_front();
        }
        return results;
    }

    void restoreTaskResults(const std::vector<C2Message>& results)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto it = results.rbegin(); it != results.rend(); ++it)
            if (m_messageToRead.size() < MaxPendingMessages)
                m_messageToRead.push_front(*it);
    }


    // Adds a new SessionListener to the current session if one with the same hash doesn't already exist.
    // Returns true if the listener was successfully added, false if it already exists.
    bool addListener(const std::string& listenerHash, const std::string& type,
                    const std::string& param1, const std::string& param2)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& listener : m_sessionListener)
            if (listener.getListenerHash() == listenerHash)
                return false;
        if (m_sessionListener.size() >= MaxChildListeners)
            return false;
        m_sessionListener.emplace_back(listenerHash, type, param1, param2);
        return true;
    }


    bool rmListener(const std::string& listenerHash)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessionListener.begin();
        while(it != m_sessionListener.end()) 
        {
            if((*it).getListenerHash() == listenerHash) 
            {
                it = m_sessionListener.erase(it);
                return true;
            } 
            else 
            {
                it++;
            }
        }
        return false;
    }

    std::vector<SessionListener> getListener() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_sessionListener;
    }

    bool hasPendingMessages() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return !m_messageToSend.empty() || !m_messageToRead.empty();
    }


private:
    mutable std::mutex m_mutex;
    std::deque<C2Message> m_messageToRead;
    std::deque<C2Message> m_messageToSend;
    std::unordered_set<std::string> m_resultFingerprints;
    std::deque<std::string> m_resultFingerprintOrder;

    std::chrono::steady_clock::time_point m_lastProofOfLife;

    std::string m_listenerHash;
    std::string m_beaconHash;
    std::string m_hostname;
    std::string m_username;
    std::string m_arch;
    std::string m_privilege;
    std::string m_os;
    std::string m_internalIps;
    std::string m_processId;
    std::string m_additionalInformation;

    std::vector<SessionListener> m_sessionListener;

    std::atomic<bool> m_killed;
};


// Represente a Socks tunnel from the TeamServer to a beacon
// Tasks are configuration informations on what ip/port to target and tcp traffic that is tunneled
// In C2Message we use instruction/cmd/data
class SocksSession
{
public:
    static constexpr std::size_t MaxPendingMessages = 4096;
    SocksSession(const std::string& listenerHash, const std::string& beaconHash)
    {
        m_listenerHash=listenerHash;
        m_beaconHash=beaconHash;
    }

    std::string getListenerHash() const
    {
        return m_listenerHash;
    }

    std::string getBeaconHash() const
    {
        return m_beaconHash;
    }

    int addTask(const C2Message& task)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_messageToSend.size() >= MaxPendingMessages)
            return -1;
        m_messageToSend.push_back(task);
        return static_cast<int>(m_messageToSend.size());
    }

    C2Message getTask()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if(!m_messageToSend.empty())
        {
            C2Message output = std::move(m_messageToSend.front());
            m_messageToSend.pop_front();
            return output;
        }
        return C2Message();
    }

    int addTaskResult(const C2Message& taskResult)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_messageToRead.size() >= MaxPendingMessages)
            return -1;
        m_messageToRead.push_back(taskResult);
        return static_cast<int>(m_messageToRead.size());
    }

    C2Message getTaskResult()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if(!m_messageToRead.empty())
        {
            C2Message output = std::move(m_messageToRead.front());
            m_messageToRead.pop_front();
            return output;
        }
        return C2Message();
    }


private:
    mutable std::mutex m_mutex;
    std::deque<C2Message> m_messageToRead;
    std::deque<C2Message> m_messageToSend;

    std::string m_listenerHash;
    std::string m_beaconHash;
};
