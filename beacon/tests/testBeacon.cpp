#include <catch2/catch_test_macros.hpp>
#include "../Beacon.hpp"
#include "../../modules/ModuleCmd/CommonCommand.hpp"

class BeaconTestProxy : public Beacon {
public:
    using Beacon::initConfig;
    using Beacon::cmdToTasks;
    using Beacon::taskResultsToCmd;
    using Beacon::execInstruction;

    void checkIn() override {}

    void pushTask(const C2Message &msg) { m_tasks.push(msg); }
    void pushResult(const C2Message &msg) { m_taskResult.push(msg); }
    size_t resultCount() const { return m_taskResult.size(); }
    size_t taskCount() const { return m_tasks.size(); }
};

static const std::string kConfig = R"({"xorKey":"key","ModulesConfig":{}})";

TEST_CASE("initConfig parses xor key", "[beacon]") {
    BeaconTestProxy b;
    REQUIRE(b.initConfig(kConfig));
}

TEST_CASE("initConfig validates input", "[beacon]") {
    BeaconTestProxy b;
    REQUIRE_FALSE(b.initConfig("not json"));
    REQUIRE_FALSE(b.initConfig(R"({"xorKey":"k"})"));
}

TEST_CASE("cmdToTasks handles malformed input", "[beacon]") {
    BeaconTestProxy b;
    b.initConfig(kConfig);
    REQUIRE(b.cmdToTasks("not_base64"));
    REQUIRE(b.taskCount() == 0);
}

TEST_CASE("taskResultsToCmd serializes queued results", "[beacon]") {
    BeaconTestProxy b;
    b.initConfig(kConfig);
    C2Message msg; msg.set_instruction("TEST"); msg.set_returnvalue("OK");
    b.pushResult(msg);
    std::string out;
    REQUIRE(b.taskResultsToCmd(out));
    REQUIRE_FALSE(out.empty());
    REQUIRE(b.resultCount() == 0); // queue cleared
}

TEST_CASE("execInstruction handles Sleep and End", "[beacon]") {
    BeaconTestProxy b;

    C2Message sleepMsg; sleepMsg.set_instruction(SleepCmd); sleepMsg.set_cmd("2");
    C2Message sleepRet;
    REQUIRE_FALSE(b.execInstruction(sleepMsg, sleepRet));
    REQUIRE(sleepRet.returnvalue() == "2000ms");

    C2Message badSleep; badSleep.set_instruction(SleepCmd); badSleep.set_cmd("abc");
    C2Message badRet;
    REQUIRE_FALSE(b.execInstruction(badSleep, badRet));
    REQUIRE(badRet.returnvalue() == CmdStatusFail);

    C2Message endMsg; endMsg.set_instruction(EndCmd);
    C2Message endRet;
    REQUIRE(b.execInstruction(endMsg, endRet));
    REQUIRE(endRet.returnvalue() == CmdStatusSuccess);
}

TEST_CASE("execInstruction unknown module", "[beacon]") {
    BeaconTestProxy b;
    C2Message msg; msg.set_instruction("UNKNOWN");
    C2Message ret;
    REQUIRE_FALSE(b.execInstruction(msg, ret));
    REQUIRE(ret.returnvalue() == CmdModuleNotFound);
}
