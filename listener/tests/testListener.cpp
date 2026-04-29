#include "../Listener.hpp"
#include "../Session.hpp"

#include <iostream>
#include <memory>
#include <string>

class ListenerTestProxy : public Listener {
public:
    ListenerTestProxy() : Listener("p1", "p2", "tcp") {}
    using Listener::addTask;
    using Listener::getTask;
    using Listener::addTaskResult;
    using Listener::getTaskResult;
    using Listener::addSessionListener;
    using Listener::rmSessionListener;

    void addSession(const std::shared_ptr<Session>& s) { m_sessions.push_back(s); }
};

namespace {
    bool expect(bool condition, const std::string& message)
    {
        if (!condition)
        {
            std::cerr << "[FAIL] " << message << std::endl;
            return false;
        }
        return true;
    }

    std::shared_ptr<Session> makeSession()
    {
        return std::make_shared<Session>("lhash", "bhash", "host", "user", "arch", "priv", "os");
    }
}

int main()
{
    bool ok = true;

    {
        ListenerTestProxy l;
        l.addSession(makeSession());
        ok &= expect(l.addSessionListener("bhash", "child", "tcp", "p1", "p2"), "session listener should be added");
        auto infos = l.getSessionListenerInfos();
        ok &= expect(infos.size() == 1, "session listener info should be visible");
        ok &= expect(l.rmSessionListener("bhash", "child"), "session listener should be removed");
    }
    {
        ListenerTestProxy l;
        l.addSession(makeSession());
        C2Message msg;
        msg.set_instruction("CMD");
        ok &= expect(l.addTask(msg, "bhash"), "task should be queued for session");
        std::string hash = "bhash";
        auto retrieved = l.getTask(hash);
        ok &= expect(retrieved.instruction() == "CMD", "queued task should be retrievable");
    }
    {
        ListenerTestProxy l;
        l.addSession(makeSession());
        C2Message msg;
        msg.set_instruction("RES");
        std::string hash = "bhash";
        ok &= expect(l.addTaskResult(msg, hash), "task result should be queued for session");
        auto out = l.getTaskResult(hash);
        ok &= expect(out.instruction() == "RES", "queued task result should be retrievable");
    }

    return ok ? 0 : 1;
}
