#include "../../MkDir/MkDir.hpp"
#include "../../ListDirectory/ListDirectory.hpp"
#include "../../ChangeDirectory/ChangeDirectory.hpp"
#include "../../PrintWorkingDirectory/PrintWorkingDirectory.hpp"
#include "../TestHelpers.hpp"
#include "MessageTestHelpers.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

int main()
{
    namespace fs = std::filesystem;
    using test_helpers::expect;
    using test_helpers::roundTripMessage;

    const fs::path original = fs::current_path();
    const fs::path root = fs::temp_directory_path() /
        ("c2core_local_contract_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(root);
    bool ok = true;

    MkDir mkPreparer;
    MkDir mkExecutor;
    MkDir mkReceiver;
    std::vector<std::string> missingMkArgs{"mkDir"};
    C2Message missingMkRequest;
    ok &= expect(mkPreparer.init(missingMkArgs, missingMkRequest) == -1,
        "mkDir rejects a missing path");
    const fs::path created = root / "dir with spaces";
    std::vector<std::string> mkArgs{"mkDir", (root / "dir").string(), "with", "spaces"};
    C2Message mkPrepared;
    ok &= expect(mkPreparer.init(mkArgs, mkPrepared) == 0, "mkDir prepares a path containing spaces");
    C2Message mkRequest = roundTripMessage(mkPrepared);
    ok &= expect(mkRequest.cmd() == created.string() && !fs::exists(created),
        "mkDir serializes the path before the directory exists");
    C2Message mkResult;
    mkExecutor.process(mkRequest, mkResult);
    C2Message mkResponse = roundTripMessage(mkResult);
    ok &= expect(mkResponse.instruction() == mkRequest.instruction()
        && mkResponse.errorCode() == 0 && fs::is_directory(created)
        && mkResponse.returnvalue() == "Directory created.", "mkDir reports creation in its response");
    mkExecutor.process(mkRequest, mkResult);
    mkResponse = roundTripMessage(mkResult);
    ok &= expect(mkResponse.errorCode() == 0 && mkResponse.returnvalue() == "Already exists.",
        "mkDir reports an existing directory as success");

    const fs::path file = root / "file.txt";
    std::ofstream(file) << "sample";
    mkArgs = {"mkDir", (file / "child").string()};
    ok &= expect(mkPreparer.init(mkArgs, mkPrepared) == 0, "mkDir accepts a path before execution");
    mkRequest = roundTripMessage(mkPrepared);
    mkExecutor.process(mkRequest, mkResult);
    mkResponse = roundTripMessage(mkResult);
    std::string error;
    mkReceiver.errorCodeToMsg(mkResponse, error);
    ok &= expect(mkResponse.instruction() == mkRequest.instruction()
        && mkResponse.errorCode() == 1 && mkResponse.returnvalue().empty()
        && error == "Failed: Could not create directory",
        "mkDir translates the received failure code");

    ListDirectory lsPreparer;
    ListDirectory lsExecutor;
    ListDirectory lsReceiver;
    std::vector<std::string> lsArgs{"ls", root.string()};
    C2Message lsPrepared;
    ok &= expect(lsPreparer.init(lsArgs, lsPrepared) == 0, "ls prepares the directory path");
    C2Message lsRequest = roundTripMessage(lsPrepared);
    C2Message lsResult;
    lsExecutor.process(lsRequest, lsResult);
    C2Message lsResponse = roundTripMessage(lsResult);
    ok &= expect(lsResponse.instruction() == lsRequest.instruction() && lsResponse.errorCode() == 0
        && lsResponse.returnvalue().find(file.string()) != std::string::npos,
        "ls lists a file and reports success");
    lsArgs = {"ls", (root / "missing").string()};
    ok &= expect(lsPreparer.init(lsArgs, lsPrepared) == 0, "ls prepares a missing path");
    lsRequest = roundTripMessage(lsPrepared);
    lsExecutor.process(lsRequest, lsResult);
    lsResponse = roundTripMessage(lsResult);
    error.clear();
    lsReceiver.errorCodeToMsg(lsResponse, error);
    ok &= expect(lsResponse.instruction() == lsRequest.instruction()
        && lsResponse.errorCode() == 1 && lsResponse.returnvalue().empty()
        && error == "Failed: Could not list directory",
        "ls translates the received failure code");
    C2Message codeOnly;
    codeOnly.set_errorCode(1);
    error.clear();
    lsReceiver.errorCodeToMsg(codeOnly, error);
    ok &= expect(error == "Failed: Could not list directory", "ls translates a code without a diagnostic");
    lsArgs = {"ls", file.string()};
    ok &= expect(lsPreparer.init(lsArgs, lsPrepared) == 0, "ls prepares a file path");
    lsRequest = roundTripMessage(lsPrepared);
    lsExecutor.process(lsRequest, lsResult);
    lsResponse = roundTripMessage(lsResult);
    ok &= expect(lsResponse.errorCode() == 1 && lsResponse.returnvalue().empty(),
        "ls rejects a file supplied as a directory with empty output");

    ChangeDirectory cdPreparer;
    ChangeDirectory cdExecutor;
    ChangeDirectory cdReceiver;
    std::vector<std::string> emptyCdArgs;
    C2Message emptyCdRequest;
    ok &= expect(cdPreparer.init(emptyCdArgs, emptyCdRequest) == -1,
        "cd rejects an empty argument vector");
    std::vector<std::string> cdArgs{"cd", created.string()};
    C2Message cdPrepared;
    ok &= expect(cdPreparer.init(cdArgs, cdPrepared) == 0, "cd prepares a path");
    C2Message cdRequest = roundTripMessage(cdPrepared);
    C2Message cdResult;
    cdExecutor.process(cdRequest, cdResult);
    C2Message cdResponse = roundTripMessage(cdResult);
    ok &= expect(cdResponse.instruction() == cdRequest.instruction()
        && cdResponse.errorCode() == 0 && fs::current_path() == created,
        "cd changes the executor's working directory");

    PrintWorkingDirectory pwdPreparer;
    PrintWorkingDirectory pwdExecutor;
    std::vector<std::string> extraPwdArgs{"pwd", "unexpected"};
    C2Message invalidPwdRequest;
    ok &= expect(pwdPreparer.init(extraPwdArgs, invalidPwdRequest) == -1,
        "pwd rejects extra arguments");
    std::vector<std::string> pwdArgs{"pwd"};
    C2Message pwdPrepared;
    ok &= expect(pwdPreparer.init(pwdArgs, pwdPrepared) == 0, "pwd prepares a request");
    C2Message pwdRequest = roundTripMessage(pwdPrepared);
    C2Message pwdResult;
    pwdExecutor.process(pwdRequest, pwdResult);
    const C2Message pwdResponse = roundTripMessage(pwdResult);
    ok &= expect(pwdResponse.instruction() == pwdRequest.instruction()
        && pwdResponse.errorCode() == 0 && pwdResponse.returnvalue() == created.string(),
        "pwd observes the executor's current directory");
    PrintWorkingDirectory pwdReceiver;
    codeOnly.set_errorCode(1);
    error.clear();
    pwdReceiver.errorCodeToMsg(codeOnly, error);
    ok &= expect(error == "Failed: Could not read working directory",
        "pwd translates a received error code without a diagnostic");

    cdArgs = {"cd", (root / "missing").string()};
    ok &= expect(cdPreparer.init(cdArgs, cdPrepared) == 0, "cd prepares a path that may be absent remotely");
    cdRequest = roundTripMessage(cdPrepared);
    cdExecutor.process(cdRequest, cdResult);
    cdResponse = roundTripMessage(cdResult);
    error.clear();
    cdReceiver.errorCodeToMsg(cdResponse, error);
    ok &= expect(cdResponse.instruction() == cdRequest.instruction()
        && cdResponse.errorCode() == 1 && cdResponse.returnvalue().empty()
        && fs::current_path() == created
        && error == "Failed: Could not change directory", "cd reports failure and preserves the working directory");

    fs::current_path(original);
    fs::remove_all(root);
    return ok ? 0 : 1;
}
