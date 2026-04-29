#include "../Beacon.hpp"
#include "../../modules/ModuleCmd/CommonCommand.hpp"

#include <iostream>
#include <string>

class BeaconTestProxy : public Beacon {
public:
    using Beacon::initConfig;
    using Beacon::cmdToTasks;
    using Beacon::taskResultsToCmd;
    using Beacon::execInstruction;

    void checkIn() override {}

    void pushResult(const C2Message& msg) { m_taskResult.push(msg); }
    size_t resultCount() const { return m_taskResult.size(); }
    size_t taskCount() const { return m_tasks.size(); }
};

namespace {
    const std::string kConfig = R"({"xorKey":"key","ModulesConfig":{}})";

    bool expect(bool condition, const std::string& message)
    {
        if (!condition)
        {
            std::cerr << "[FAIL] " << message << std::endl;
            return false;
        }
        return true;
    }
}

int main()
{
    bool ok = true;

    {
        BeaconTestProxy b;
        ok &= expect(b.initConfig(kConfig), "initConfig should parse xor key");
    }
    {
        BeaconTestProxy b;
        ok &= expect(!b.initConfig("not json"), "initConfig should reject malformed JSON");
        ok &= expect(!b.initConfig(R"({"xorKey":"k"})"), "initConfig should reject incomplete config");
    }
    {
        BeaconTestProxy b;
        ok &= expect(b.initConfig(kConfig), "initConfig should accept base config");
        ok &= expect(b.cmdToTasks("not_base64"), "cmdToTasks should tolerate malformed input");
        ok &= expect(b.taskCount() == 0, "cmdToTasks should not enqueue malformed tasks");
    }
    {
        BeaconTestProxy b;
        ok &= expect(b.initConfig(kConfig), "initConfig should accept base config for results");
        C2Message msg;
        msg.set_instruction("TEST");
        msg.set_returnvalue("OK");
        b.pushResult(msg);
        std::string out;
        ok &= expect(b.taskResultsToCmd(out), "taskResultsToCmd should serialize queued results");
        ok &= expect(!out.empty(), "serialized task results should not be empty");
        ok &= expect(b.resultCount() == 0, "taskResultsToCmd should clear result queue");
    }
    {
        BeaconTestProxy b;
        C2Message sleepMsg;
        sleepMsg.set_instruction(SleepCmd);
        sleepMsg.set_cmd("2");
        C2Message sleepRet;
        ok &= expect(!b.execInstruction(sleepMsg, sleepRet), "sleep command should keep beacon running");
        ok &= expect(sleepRet.returnvalue() == "2000ms", "sleep command should convert seconds to ms");

        C2Message badSleep;
        badSleep.set_instruction(SleepCmd);
        badSleep.set_cmd("abc");
        C2Message badRet;
        ok &= expect(!b.execInstruction(badSleep, badRet), "bad sleep should keep beacon running");
        ok &= expect(badRet.returnvalue() == CmdStatusFail, "bad sleep should fail cleanly");

        C2Message endMsg;
        endMsg.set_instruction(EndCmd);
        C2Message endRet;
        ok &= expect(b.execInstruction(endMsg, endRet), "end command should stop beacon");
        ok &= expect(endRet.returnvalue() == CmdStatusSuccess, "end command should return success");
    }
    {
        BeaconTestProxy b;
        C2Message msg;
        msg.set_instruction("UNKNOWN");
        C2Message ret;
        ok &= expect(!b.execInstruction(msg, ret), "unknown module should keep beacon running");
        ok &= expect(ret.returnvalue() == CmdModuleNotFound, "unknown module should report module not found");
    }

    return ok ? 0 : 1;
}
