#include "../MkDir.hpp"
#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <thread>

bool testMkDir();

static std::filesystem::path uniqueTestTempPath(const char* prefix)
{
    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())
        + "_" + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));
    return std::filesystem::temp_directory_path() / (std::string(prefix) + "_" + suffix);
}

int main()
{
    bool res;
    std::cout << "[+] testMkDir" << std::endl;
    res = testMkDir();
    if (res)
        std::cout << "[+] Sucess" << std::endl;
    else
        std::cout << "[-] Failed" << std::endl;

    return !res;
}

bool testMkDir()
{
    namespace fs = std::filesystem;
    fs::path temp = uniqueTestTempPath("c2core_mkdir_test");
    fs::remove_all(temp);
    bool ok = true;

    {
        MkDir mk;
        std::vector<std::string> cmd = {"mkDir", temp.string()};
        C2Message msg, ret;
        mk.init(cmd, msg);
        msg.set_cmd(temp.string());
        mk.process(msg, ret);
        ok &= ret.returnvalue().find("Directory created") != std::string::npos;
        ok &= fs::exists(temp);
    }

    {
        MkDir mk;
        std::vector<std::string> cmd = {"mkDir", temp.string()};
        C2Message msg, ret;
        mk.init(cmd, msg);
        msg.set_cmd(temp.string());
        mk.process(msg, ret);
        ok &= ret.returnvalue().find("Already exists") != std::string::npos;
    }

    fs::remove_all(temp);
    return ok;
}
