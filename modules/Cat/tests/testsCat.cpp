#include "../Cat.hpp"
#include "../../tests/TestHelpers.hpp"
#include "../../tests/local/MessageTestHelpers.hpp"

#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <thread>

bool testCat();

static std::filesystem::path uniqueTestTempPath(const char* prefix)
{
    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())
        + "_" + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));
    return std::filesystem::temp_directory_path() / (std::string(prefix) + "_" + suffix);
}

int main()
{
    bool res;

    std::cout << "[+] testCat" << std::endl;
    res = testCat();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return !res;
}

bool testCat()
{
    namespace fs = std::filesystem;
    using test_helpers::expect;
    using test_helpers::roundTripMessage;
    fs::path temp = uniqueTestTempPath("c2core_cat_test");
    fs::create_directories(temp);

    Cat preparer;
    Cat executor;
    bool ok = expect(preparer.osCompatibility() == (OS_LINUX | OS_WINDOWS),
        "Cat declares support for Linux and Windows");

    {
        std::vector<std::string> cmd = {"cat"};
        C2Message msg;
        ok &= expect(preparer.init(cmd, msg) == -1, "Cat rejects a missing path");
        cmd.emplace_back();
        ok &= expect(preparer.init(cmd, msg) == -1, "Cat rejects an empty path");
    }

    // ----- valid file -----
    fs::path file = temp / "file.txt";
    {
        const std::string contents("hello\0world", 11);
        std::ofstream(file, std::ios::binary) << contents;
        std::vector<std::string> cmd = {"cat", file.string()};
        C2Message msg, ret;
        ok &= expect(preparer.init(cmd, msg) == 0, "Cat accepts a file path");
        C2Message request = roundTripMessage(msg);
        ok &= expect(request.instruction() == "cat" && request.inputfile() == file.string(),
            "Cat prepares the instruction and file path");
        executor.process(request, ret);
        const C2Message response = roundTripMessage(ret);
        ok &= expect(response.instruction() == request.instruction() && response.errorCode() == 0,
            "Cat preserves the instruction and reports success in the response");
        ok &= expect(response.returnvalue() == contents, "Cat returns the exact file bytes");
        Cat receiver;
        std::string error;
        receiver.errorCodeToMsg(response, error);
        ok &= expect(error.empty(), "Cat produces no error text on success");
        ok &= expect(receiver.followUp(response) == 0, "Cat accepts a received response with its default follow-up");
    }

    // ----- path containing spaces and tokens splitted -----
    fs::path spaced = temp / "space file.txt";
    {
        std::vector<std::string> cmd = {"cat", (temp / "space").string(), "file.txt"};
        C2Message msg, ret;
        ok &= expect(preparer.init(cmd, msg) == 0, "Cat accepts a split file path");
        C2Message request = roundTripMessage(msg);
        ok &= expect(request.inputfile() == spaced.string(), "Cat keeps spaces in the file path");
        std::ofstream(spaced) << "space";
        executor.process(request, ret);
        const C2Message response = roundTripMessage(ret);
        ok &= expect(response.errorCode() == 0 && response.returnvalue() == "space",
            "Cat reads the file whose path contains spaces");
    }

    // ----- missing file or directory supplied as a file -----
    for (const auto& invalid : {temp / "does_not_exist.txt", temp})
    {
        std::vector<std::string> cmd = {"cat", invalid.string()};
        C2Message msg, ret;
        ok &= expect(preparer.init(cmd, msg) == 0, "Cat accepts the requested path");
        C2Message request = roundTripMessage(msg);
        ok &= expect(request.inputfile() == invalid.string(), "Cat records the requested path");
        executor.process(request, ret);

        const C2Message response = roundTripMessage(ret);
        ok &= expect(response.instruction() == request.instruction() && response.errorCode() == 1,
            "Cat preserves the instruction and reports error code 1 for an unreadable file");
        ok &= expect(response.returnvalue().empty(), "Cat keeps file contents empty on error");
        Cat receiver;
        std::string error;
        receiver.errorCodeToMsg(response, error);
        ok &= expect(error == "Failed: Couldn't open file", "Cat translates the received file error code");
    }

    C2Message noResult;
    ok &= expect(executor.recurringExec(noResult) == 0, "Cat has no recurring result");
    fs::remove_all(temp);
    return ok;
}
