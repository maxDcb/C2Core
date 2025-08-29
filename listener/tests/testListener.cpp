#include <catch2/catch_test_macros.hpp>
#include "../Listener.hpp"
#include "../Session.hpp"

class ListenerTestProxy : public Listener {
public:
    ListenerTestProxy() : Listener("p1","p2","tcp") {}
    using Listener::addTask;
    using Listener::getTask;
    using Listener::addTaskResult;
    using Listener::getTaskResult;
    using Listener::addSessionListener;
    using Listener::rmSessionListener;
    using Listener::isSessionExist;

    void addSession(const std::shared_ptr<Session>& s) { m_sessions.push_back(s); }
};

TEST_CASE("session listener add/remove", "[listener]") {
    ListenerTestProxy l;
    auto session = std::make_shared<Session>("lhash","bhash","host","user","arch","priv","os");
    l.addSession(session);
    REQUIRE(l.addSessionListener("bhash","child","tcp","p1","p2"));
    auto infos = l.getSessionListenerInfos();
    REQUIRE(infos.size() == 1);
    REQUIRE(l.rmSessionListener("bhash","child"));
}

TEST_CASE("task queue operations", "[listener]") {
    ListenerTestProxy l;
    auto session = std::make_shared<Session>("lhash","bhash","host","user","arch","priv","os");
    l.addSession(session);
    C2Message msg; msg.set_instruction("CMD");
    REQUIRE(l.addTask(msg, "bhash"));
    std::string hash = "bhash";
    auto retrieved = l.getTask(hash);
    REQUIRE(retrieved.instruction() == "CMD");
}

TEST_CASE("task result queue operations", "[listener]") {
    ListenerTestProxy l;
    auto session = std::make_shared<Session>("lhash","bhash","host","user","arch","priv","os");
    l.addSession(session);
    C2Message msg; msg.set_instruction("RES");
    std::string hash = "bhash";
    REQUIRE(l.addTaskResult(msg, hash));
    auto out = l.getTaskResult(hash);
    REQUIRE(out.instruction() == "RES");
}
