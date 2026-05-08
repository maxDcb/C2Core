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
    bool process(const std::string& input, std::string& output) { return handleMessages(input, output); }
    std::string encode(const MultiBundleC2Message& message)
    {
        std::string data;
        const_cast<MultiBundleC2Message&>(message).SerializeToString(&data);
        XOR(data, m_key);
        return base64_encode(data);
    }
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

    std::shared_ptr<Session> makeSession(
        const std::string& listenerHash = "lhash",
        const std::string& beaconHash = "bhash")
    {
        return std::make_shared<Session>(listenerHash, beaconHash, "host", "user", "arch", "priv", "os");
    }
}

int main()
{
    bool ok = true;

    {
        ListenerTestProxy l;
        l.addSession(makeSession());
        ok &= expect(l.addSessionListener("bhash", "child", "tcp", "p1", "p2"), "session listener should be added");
        ok &= expect(!l.addSessionListener("bhash", "child", "tcp", "p1", "p2"), "duplicate session listener should not be added");
        auto infos = l.getSessionListenerInfos();
        ok &= expect(infos.size() == 1, "session listener info should be visible once");
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
    {
        const std::string beaconHash = "ABCDEFGH12345678ABCDEFGH12345678";
        ListenerTestProxy l;
        l.addSession(makeSession("lhash", beaconHash));

        MultiBundleC2Message incoming;
        BundleC2Message* bundle = incoming.add_bundlec2messages();
        bundle->set_beaconhash(beaconHash);
        bundle->set_listenerhash("lhash");
        bundle->set_lastProofOfLife("0");

        C2Message* poll = bundle->add_c2messages();
        poll->set_instruction(ListenerPollCmd);
        poll->set_data(R"({"1":"tcp","2":"0.0.0.0","3":"4444"})");
        poll->set_returnvalue("child-listener");

        std::string output;
        l.process(l.encode(incoming), output);

        auto infos = l.getSessionListenerInfos();
        ok &= expect(infos.size() == 1, "listener poll should update session listener metadata");
        ok &= expect(infos[0].getListenerHash() == "child-listener", "listener poll should preserve child listener hash");
        ok &= expect(infos[0].getType() == "tcp", "listener poll should preserve child listener type");

        auto result = l.getTaskResult(beaconHash);
        ok &= expect(result.instruction().empty(), "listener poll should not be queued as a command result");
    }
    {
        const std::string beaconHash = "ABCDEFGH12345678ABCDEFGH12345678";
        ListenerTestProxy l;
        l.addSession(makeSession("lhash", beaconHash));

        MultiBundleC2Message incoming;
        BundleC2Message* bundle = incoming.add_bundlec2messages();
        bundle->set_beaconhash(beaconHash);
        bundle->set_listenerhash("lhash");
        bundle->set_lastProofOfLife("0");

        C2Message* poll = bundle->add_c2messages();
        poll->set_instruction(ListenerPollCmd);
        poll->set_data("child-listener");
        poll->set_returnvalue(R"({"1":"tcp","2":"0.0.0.0","3":"4444"})");

        std::string output;
        l.process(l.encode(incoming), output);

        auto infos = l.getSessionListenerInfos();
        ok &= expect(infos.size() == 1, "legacy listener poll should update session listener metadata");
        ok &= expect(infos[0].getListenerHash() == "child-listener", "legacy listener poll should preserve child listener hash");
        ok &= expect(infos[0].getType() == "tcp", "legacy listener poll should preserve child listener type");
    }

    return ok ? 0 : 1;
}
