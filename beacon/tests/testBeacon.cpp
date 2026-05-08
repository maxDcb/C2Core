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
    const std::string& arch() const { return m_arch; }
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

    std::string buildProcessArch()
    {
#if defined(_M_IX86) || defined(__i386__)
        return "x86";
#elif defined(_M_X64) || defined(__x86_64__)
        return "x64";
#elif defined(_M_ARM64) || defined(__aarch64__)
        return "arm64";
#elif defined(_M_ARM) || defined(__arm__)
        return "arm";
#else
        return "unknown";
#endif
    }
}

int main()
{
    bool ok = true;

    {
        BeaconTestProxy b;
        ok &= expect(b.initConfig(kConfig), "initConfig should parse xor key");
        ok &= expect(b.arch() == buildProcessArch(), "beacon arch should report process architecture");
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

        C2Message badListenerPort;
        badListenerPort.set_instruction(ListenerCmd);
        badListenerPort.set_cmd(StartCmd + " " + ListenerTcpType + " 0.0.0.0 notaport");
        C2Message badListenerRet;
        ok &= expect(!b.execInstruction(badListenerPort, badListenerRet), "bad listener port should keep beacon running");
        ok &= expect(badListenerRet.errorCode() == ERROR_PORT_FORMAT, "bad listener port should be rejected");

        C2Message zeroListenerPort;
        zeroListenerPort.set_instruction(ListenerCmd);
        zeroListenerPort.set_cmd(StartCmd + " " + ListenerTcpType + " 0.0.0.0 0");
        C2Message zeroListenerRet;
        ok &= expect(!b.execInstruction(zeroListenerPort, zeroListenerRet), "zero listener port should keep beacon running");
        ok &= expect(zeroListenerRet.errorCode() == ERROR_PORT_FORMAT, "zero listener port should be rejected");
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
