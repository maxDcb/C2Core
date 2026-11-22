#include "../Tree.hpp"
#include "../../tests/TestHelpers.hpp"
#include "../../tests/local/MessageTestHelpers.hpp"

#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <thread>

bool testTree();

static std::filesystem::path uniqueTestTempPath(const char* prefix)
{
    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())
        + "_" + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));
    return std::filesystem::temp_directory_path() / (std::string(prefix) + "_" + suffix);
}

int main()
{
    bool res;

    std::cout << "[+] testTree" << std::endl;
    res = testTree();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return !res;
}

bool testTree()
{
    namespace fs = std::filesystem;
    using test_helpers::expect;
    using test_helpers::roundTripMessage;
    fs::path temp = uniqueTestTempPath("c2core_tree_test");
    fs::create_directories(temp / "sub");
    std::ofstream(temp / "file.txt") << "data";
    std::ofstream(temp / "sub" / "inner.txt") << "data";

    Tree preparer;
    Tree executor;
    bool ok = expect(preparer.osCompatibility() == (OS_LINUX | OS_WINDOWS),
        "Tree declares support for Linux and Windows");

    {
        std::vector<std::string> cmd;
        C2Message msg;
        ok &= expect(preparer.init(cmd, msg) == -1, "Tree rejects an empty argument vector");
    }

    // ----- explicit path -----
    {
        std::vector<std::string> cmd = {"tree", temp.string()};
        C2Message msg, ret;
        ok &= expect(preparer.init(cmd, msg) == 0, "Tree accepts a directory path");
        C2Message request = roundTripMessage(msg);
        ok &= expect(request.instruction() == "tree" && request.cmd() == temp.string(),
            "Tree prepares the instruction and directory path");
        executor.process(request, ret);
        const C2Message response = roundTripMessage(ret);
        ok &= expect(response.errorCode() == 0, "Tree reports success in the response");
        const auto& out = response.returnvalue();
        ok &= expect(out.find((temp / "file.txt").string()) != std::string::npos,
            "Tree lists the top-level file");
        ok &= expect(out.find((temp / "sub" / "inner.txt").string()) != std::string::npos,
            "Tree lists files in subdirectories");
        Tree receiver;
        std::string error;
        receiver.errorCodeToMsg(response, error);
        ok &= expect(error.empty(), "Tree produces no error text on success");
        ok &= expect(receiver.followUp(response) == 0, "Tree accepts a received response with its default follow-up");
    }

    // ----- path with spaces using split tokens -----
    fs::path spacedDir = temp / "dir space";
    {
        std::vector<std::string> cmd = {"tree", (temp / "dir").string(), "space"};
        C2Message msg, ret;
        ok &= expect(preparer.init(cmd, msg) == 0, "Tree accepts a split directory path");
        C2Message request = roundTripMessage(msg);
        ok &= expect(request.cmd() == spacedDir.string(), "Tree keeps spaces in the directory path");
        fs::create_directories(spacedDir);
        std::ofstream(spacedDir / "dummy.txt") << "a";
        executor.process(request, ret);
        const C2Message response = roundTripMessage(ret);
        ok &= expect(response.errorCode() == 0
            && response.returnvalue().find((spacedDir / "dummy.txt").string()) != std::string::npos,
            "Tree lists files in a directory whose path contains spaces");
    }

    // ----- missing directory or file supplied as a directory -----
    for (const auto& invalid : {temp / "does_not_exist", temp / "file.txt"})
    {
        std::vector<std::string> cmd = {"tree", invalid.string()};
        C2Message msg, ret;
        ok &= expect(preparer.init(cmd, msg) == 0, "Tree accepts the requested path");
        C2Message request = roundTripMessage(msg);
        ok &= expect(request.cmd() == invalid.string(), "Tree records the requested path");
        executor.process(request, ret);

        const C2Message response = roundTripMessage(ret);
        ok &= expect(response.errorCode() == 1, "Tree reports error code 1 for an unreadable directory");
        ok &= expect(response.returnvalue().find("Error:") == 0, "Tree preserves the filesystem diagnostic");
        Tree receiver;
        const std::string summary = "Failed: Couldn't list directory";
        std::string error;
        receiver.errorCodeToMsg(response, error);
        ok &= expect(error == summary + "\n" + response.returnvalue(),
            "Tree translates the received error code and includes the diagnostic");

        C2Message codeOnly;
        codeOnly.set_errorCode(response.errorCode());
        receiver.errorCodeToMsg(codeOnly, error);
        ok &= expect(error == summary, "Tree translates the error code without a diagnostic");
    }

    // ----- no argument -----
    {
        const fs::path original = fs::current_path();
        std::vector<std::string> cmd = {"tree"};
        C2Message msg, ret;
        ok &= expect(preparer.init(cmd, msg) == 0, "Tree accepts an omitted path");
        C2Message request = roundTripMessage(msg);
        ok &= expect(request.cmd().empty(), "Tree leaves an omitted path empty");
        fs::current_path(temp);
        executor.process(request, ret);
        fs::current_path(original);
        const C2Message response = roundTripMessage(ret);
        ok &= expect(response.errorCode() == 0
            && response.returnvalue().find((temp / "file.txt").string()) != std::string::npos,
            "Tree uses the execution directory when the path is omitted");
    }

    C2Message noResult;
    ok &= expect(executor.recurringExec(noResult) == 0, "Tree has no recurring result");

    fs::remove_all(temp);
    return ok;
}
