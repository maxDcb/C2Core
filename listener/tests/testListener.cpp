#include "../Listener.hpp"
#include "../Session.hpp"

#include <iostream>
#include <memory>
#include <string>
#include <atomic>
#include <thread>

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
        l.addSession(makeSession("route-a", "shared-beacon"));
        l.addSession(makeSession("route-b", "shared-beacon"));
        C2Message first;
        first.set_instruction("ROUTE-A");
        C2Message second;
        second.set_instruction("ROUTE-B");
        ok &= expect(!l.queueTask("shared-beacon", first),
            "beacon-only routing should reject an ambiguous session");
        ok &= expect(l.queueTask("shared-beacon", "route-a", first),
            "exact route A should accept its task");
        ok &= expect(l.queueTask("shared-beacon", "route-b", second),
            "exact route B should accept its task");
        ok &= expect(l.getTask("shared-beacon", "route-a").instruction() == "ROUTE-A",
            "route A should not consume route B task");
        ok &= expect(l.getTask("shared-beacon", "route-b").instruction() == "ROUTE-B",
            "route B should not consume route A task");
    }
    {
        auto session = makeSession();
        C2Message stop;
        stop.set_instruction(EndCmd);
        const auto requestedAt = std::chrono::steady_clock::now();
        ok &= expect(session->queueStopTask(stop, requestedAt), "initial stop should queue");
        ok &= expect(!session->queueStopTask(stop, requestedAt + std::chrono::seconds(1)),
            "stop should reject an immediate duplicate");
        ok &= expect(session->getLifecycleState(requestedAt + std::chrono::seconds(31))
            == Session::LifecycleState::StopFailed, "stop should become unconfirmed after deadline");
        ok &= expect(session->queueStopTask(stop, requestedAt + std::chrono::seconds(31)),
            "unconfirmed stop should allow retry");
        ok &= expect(session->getLifecycleState(requestedAt + std::chrono::seconds(31))
            == Session::LifecycleState::Stopping, "retry should restore stopping state");
        ok &= expect(session->getTask().instruction() == EndCmd
            && session->getTask().instruction().empty(), "retry should not duplicate an undelivered task");
    }
    {
        const std::string beaconHash = "ENDCONFIRM123456ENDCONFIRM123456";
        ListenerTestProxy listener;
        auto session = makeSession("route", beaconHash);
        listener.addSession(session);
        C2Message stop;
        stop.set_instruction(EndCmd);
        ok &= expect(listener.queueStopTaskIfSessionAlive(beaconHash, "route", stop),
            "stop should queue before confirmation");
        ok &= expect(listener.getTask(beaconHash, "route").instruction() == EndCmd,
            "stop task should be delivered on the exact route");
        ok &= expect(session->getLifecycleState() == Session::LifecycleState::Stopping,
            "delivery alone must not confirm termination");

        MultiBundleC2Message response;
        auto* bundle = response.add_bundlec2messages();
        bundle->set_beaconhash(beaconHash);
        bundle->set_listenerhash("route");
        bundle->set_lastProofOfLife("0");
        auto* confirmed = bundle->add_c2messages();
        confirmed->set_instruction(EndCmd);
        confirmed->set_errorCode(1);
        confirmed->set_returnvalue(CmdStatusFail);
        std::string output;
        listener.process(listener.encode(response), output);
        ok &= expect(session->getLifecycleState() == Session::LifecycleState::Stopping,
            "failed EndCmd result must not confirm termination");
        confirmed->set_errorCode(0);
        confirmed->set_returnvalue(CmdStatusSuccess);
        listener.process(listener.encode(response), output);
        ok &= expect(session->getLifecycleState() == Session::LifecycleState::Stopped,
            "EndCmd result should confirm termination");
        ok &= expect(listener.pruneStoppedSessions() == 0,
            "confirmed session should remain visible briefly");
    }
    {
        const std::string beaconHash = "RELAYEDSTOP12345RELAYEDSTOP12345";
        ListenerTestProxy listener;
        auto session = makeSession("child-route", beaconHash);
        listener.addSession(session);
        MultiBundleC2Message response;
        auto* bundle = response.add_bundlec2messages();
        bundle->set_beaconhash(beaconHash);
        bundle->set_listenerhash("child-route");
        bundle->set_lastProofOfLife("-1");
        std::string output;
        listener.process(listener.encode(response), output);
        ok &= expect(session->isSessionKilled(),
            "a stopped child relayed by its parent should remain a known stopped session");
    }
    {
        ListenerTestProxy l;
        auto session = makeSession();
        l.addSession(session);
        C2Message command;
        command.set_instruction("CMD");
        C2Message stop;
        stop.set_instruction(EndCmd);

        ok &= expect(l.queueTaskIfSessionAlive("bhash", "lhash", command),
            "command should queue for a live session");
        ok &= expect(l.queueStopTaskIfSessionAlive("bhash", "lhash", stop),
            "stop task should queue for a live session");
        ok &= expect(!session->isSessionKilled(), "queued stop must await beacon confirmation");
        ok &= expect(session->getLifecycleState() == Session::LifecycleState::Stopping,
            "queued stop should expose stopping state");
        ok &= expect(session->getLifecycleState(std::chrono::steady_clock::now() + std::chrono::seconds(31))
            == Session::LifecycleState::StopFailed, "unconfirmed stop should time out");
        ok &= expect(l.isSessionExist("bhash", "lhash"),
            "stopped session should remain known for beacon check-ins");
        ok &= expect(!l.queueTaskIfSessionAlive("bhash", "lhash", command),
            "command should be rejected after stop");
        ok &= expect(!l.queueStopTaskIfSessionAlive("bhash", "lhash", stop),
            "duplicate stop task should be rejected");
        ok &= expect(l.getTask("bhash").instruction() == "CMD", "accepted command should precede stop");
        ok &= expect(l.getTask("bhash").instruction() == EndCmd, "stop task should follow accepted commands");
        ok &= expect(l.getTask("bhash").instruction().empty(), "stopped session should have no later tasks");
        session->setSessionKilled();
        ok &= expect(session->getLifecycleState() == Session::LifecycleState::Stopped,
            "beacon confirmation should expose stopped state");
        ok &= expect(l.pruneStoppedSessions() == 0,
            "confirmed stop should remain visible during the confirmation window");
        ok &= expect(session->canPruneStopped(std::chrono::steady_clock::now() + std::chrono::seconds(31)),
            "confirmed stop should eventually be prunable");
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

        for (const std::string& invalidMetadata : {
                 R"({"1":"tcp","2":"0.0.0.0","3":"not-a-port"})",
                 R"({"1":"tcp","2":"0.0.0.0","3":"0"})",
                 R"({"1":"tcp","2":"0.0.0.0","3":"65536"})",
                 R"({"1":"tcp","2":"0.0.0.0","3":"999999999999999999999"})",
                 R"({"1":"http","2":"0.0.0.0","3":"4444"})"})
        {
            poll->set_data(invalidMetadata);
            poll->set_returnvalue("invalid-child-listener");
            l.process(l.encode(incoming), output);
            ok &= expect(l.getSessionListenerInfos().size() == 1,
                "invalid child listener metadata must not enter the session list");
        }
    }
    {
        const std::string beaconHash = "SOCKSRES12345678SOCKSRES12345678";
        ListenerTestProxy l;
        l.setIsPrimary();
        l.addSession(makeSession("route-a", beaconHash));

        MultiBundleC2Message incoming;
        BundleC2Message* bundle = incoming.add_bundlec2messages();
        bundle->set_beaconhash(beaconHash);
        bundle->set_listenerhash("route-a");
        bundle->set_lastProofOfLife("0");
        C2Message* socks = bundle->add_c2messages();
        socks->set_instruction(Socks5Cmd);
        socks->set_cmd(RunCmd);
        socks->set_pid(3);
        socks->set_uuid("generation");

        std::string output;
        l.process(l.encode(incoming), output);
        ok &= expect(l.getTaskResult(beaconHash).instruction().empty(),
            "SOCKS results must not pollute the general result queue");
        ok &= expect(l.getSocksTaskResult(beaconHash, "wrong-route").instruction().empty(),
            "SOCKS results must be isolated by listener route");
        ok &= expect(l.getSocksTaskResult(beaconHash, "route-a").pid() == 3,
            "SOCKS result should be available on its exact route");

        l.process(l.encode(incoming), output);
        l.clearSocksSession(beaconHash, "route-a");
        ok &= expect(l.getSocksTaskResult(beaconHash, "route-a").instruction().empty(),
            "clearing a SOCKS route must remove stale results");
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

    {
        const std::string beaconHash = "CONCURRENT123456CONCURRENT123456";
        ListenerTestProxy l;
        MultiBundleC2Message incoming;
        auto* bundle = incoming.add_bundlec2messages();
        bundle->set_beaconhash(beaconHash);
        bundle->set_listenerhash("listener");
        bundle->set_lastProofOfLife("0");
        const std::string encoded = l.encode(incoming);
        std::atomic<bool> start{false};
        std::vector<std::thread> workers;
        for (int i = 0; i < 24; ++i)
        {
            workers.emplace_back([&]
            {
                while (!start.load())
                    std::this_thread::yield();
                std::string response;
                l.process(encoded, response);
            });
        }
        start.store(true);
        for (auto& worker : workers)
            worker.join();
        ok &= expect(l.getNumberOfSession() == 1, "concurrent check-ins must register one session");
    }

    return ok ? 0 : 1;
}
