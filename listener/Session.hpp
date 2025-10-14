#pragma once

#include <iostream>
#include <chrono>
#include <queue>

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
    Session(const std::string& listenerHash, const std::string& beaconHash, const std::string& hostname, const std::string& username,
    const std::string& arch, const std::string& privilege, const std::string& os)
    {
        m_listenerHash=listenerHash;
        m_beaconHash=beaconHash;
        m_hostname=hostname;
        m_username=username;
        m_arch=arch;
        m_privilege=privilege;
        m_os=os;
        m_killed=false;


        auto current_time = std::chrono::system_clock::now();
        auto duration_in_seconds = std::chrono::duration<double>(current_time.time_since_epoch());
        m_lastProofOfLifeSec = duration_in_seconds.count();
    }

    const std::string& getListenerHash() const 
    {
        return m_listenerHash;
    }
    const std::string& getBeaconHash() const 
    {
        return m_beaconHash;
    }
    const std::string& getUsername() const 
    {
        return m_username;
    }
    const std::string& getHostname() const 
    {
        return m_hostname;
    }
    const std::string& getArch() const 
    {
        return m_arch;
    }
    const std::string& getPrivilege() const 
    {
        return m_privilege;
    }
    const std::string& getOs() const 
    {
        return m_os;
    }
    const std::string& getInternalIps() const 
    { 
        return m_internalIps; 
    }
    const std::string& getProcessId() const 
    { 
        return m_processId; 
    }
    const std::string& getAdditionalInformation() const 
    { 
        return m_additionalInformation; 
    }

    void setListenerHash(const std::string& listenerHash)
    {
        m_listenerHash = listenerHash;
    }
    void setBeaconHash(const std::string& beaconHash)
    {
        m_beaconHash = beaconHash;
    }
    void setUsername(const std::string& username)
    {
        m_username = username;
    }
    void setHostname(const std::string& hostname)
    {
        m_hostname = hostname;
    }
    void setArch(const std::string& arch)
    {
        m_arch = arch;
    }
    void setPrivilege(const std::string& privilege)
    {
        m_privilege = privilege;
    }
    void setOs(const std::string& os)
    {
        m_os = os;
    }
    void setInternalIps(const std::string& internalIps)
    {
        m_internalIps = internalIps;
    }
    void setProcessId(const std::string& processId)
    {
        m_processId = processId;
    }
    void setAdditionalInformation(const std::string& additionalInformation)
    {
        m_additionalInformation = additionalInformation;
    }


    void updatePoofOfLife(std::string& lastProofOfLife)
    {
        double lastProofOfLifeSec = std::stod(lastProofOfLife);

        auto current_time = std::chrono::system_clock::now();
        auto duration_in_seconds = std::chrono::duration<double>(current_time.time_since_epoch());

        m_lastProofOfLifeSec = duration_in_seconds.count()-lastProofOfLifeSec;
    }

    bool isSessionKilled()
    {
        return m_killed;
    }

    void setSessionAlive()
    {
        m_killed=false;
    }

    void setSessionKilled()
    {
        m_killed=true;
    }

    std::string getLastProofOfLife()
    {
        auto current_time = std::chrono::system_clock::now();
        auto duration_in_seconds = std::chrono::duration<double>(current_time.time_since_epoch());

        std::string output = std::to_string(duration_in_seconds.count()-m_lastProofOfLifeSec);
        if(m_killed)
            output="-1";

        return output;
    }

    int addTask(const C2Message& task)
    {
        m_messageToSend.push(task);    
        return m_messageToSend.size();
    }

    C2Message getTask()
    {
        C2Message output;
        if(!m_messageToSend.empty())
        {
            output.CopyFrom(m_messageToSend.front());
            m_messageToSend.pop();
        }
        return output;
    }

    int addTaskResult(const C2Message& taskResult)
    {
        m_messageToRead.push(taskResult);    
        return m_messageToRead.size();
    }


    C2Message getTaskResult()
    {
        if (!m_messageToRead.empty())
        {
            C2Message output = std::move(m_messageToRead.front());
            m_messageToRead.pop();
            return output;
        }
        return C2Message();
    }


    // Adds a new SessionListener to the current session if one with the same hash doesn't already exist.
    // Returns true if the listener was successfully added, false if it already exists.
    bool addListener(const std::string& listenerHash, const std::string& type,
                    const std::string& param1, const std::string& param2)
    {
        bool listenerAlreadyExists = false;

        // Check if a listener with the same hash already exists in the session
        for (int i = 0; i < m_sessionListener.size(); ++i)
        {
            if (m_sessionListener[i].getListenerHash() == listenerHash)
            {
                listenerAlreadyExists = true;
                break;  // Exit early if found
            }
        }

        // If the listener does not exist, create and add it
        if (!listenerAlreadyExists)
        {
            SessionListener sessionListener(listenerHash, type, param1, param2);
            m_sessionListener.push_back(sessionListener);
            return true;  // Successfully added
        }

        return false;  // Listener already existed, not added
    }


    bool rmListener(const std::string& listenerHash)
    {
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

    const std::vector<SessionListener>& getListener()
    {
        return m_sessionListener;
    }


private:
    std::queue<C2Message> m_messageToRead;
    std::queue<C2Message> m_messageRead;

    std::queue<C2Message> m_messageToSend;
    std::queue<C2Message> m_messageSent;

    double m_lastProofOfLifeSec;

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

    bool m_killed;
};


// Represente a Socks tunnel from the TeamServer to a beacon
// Tasks are configuration informations on what ip/port to target and tcp traffic that is tunneled
// In C2Message we use instruction/cmd/data
class SocksSession
{
public:
    SocksSession(const std::string& listenerHash, const std::string& beaconHash)
    {
        m_listenerHash=listenerHash;
        m_beaconHash=beaconHash;
    }

    std::string getListenerHash()
    {
        return m_listenerHash;
    }

    std::string getBeaconHash()
    {
        return m_beaconHash;
    }

    int addTask(const C2Message& task)
    {
        m_messageToSend.push(task);    
        return m_messageToSend.size();
    }

    C2Message getTask()
    {
        C2Message output;
        if(!m_messageToSend.empty())
        {
            output.CopyFrom(m_messageToSend.front());
            m_messageToSend.pop();
        }
        return output;
    }

    int addTaskResult(const C2Message& taskResult)
    {
        m_messageToRead.push(taskResult);    
        return m_messageToRead.size();
    }

    C2Message getTaskResult()
    {
        C2Message output;
        if(!m_messageToRead.empty())
        {
            output.CopyFrom(m_messageToRead.front());
            m_messageToRead.pop();
        }
        return output;
    }


private:
    std::queue<C2Message> m_messageToRead;
    std::queue<C2Message> m_messageRead;

    std::queue<C2Message> m_messageToSend;
    std::queue<C2Message> m_messageSent;

    std::string m_listenerHash;
    std::string m_beaconHash;
};
