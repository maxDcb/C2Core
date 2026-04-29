#include "../Remove.hpp"
#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <thread>

bool testRemove();

static std::filesystem::path uniqueTestTempPath(const char* prefix)
{
    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())
        + "_" + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));
    return std::filesystem::temp_directory_path() / (std::string(prefix) + "_" + suffix);
}

int main()
{
    bool res;
    std::cout << "[+] testRemove" << std::endl;
    res = testRemove();
    if (res)
        std::cout << "[+] Sucess" << std::endl;
    else
        std::cout << "[-] Failed" << std::endl;

    return !res;
}

bool testRemove()
{
    namespace fs = std::filesystem;
    fs::path temp = uniqueTestTempPath("c2core_remove_test");
    fs::remove_all(temp);
    fs::create_directories(temp / "sub");
    std::ofstream(temp / "sub" / "file.txt") << "data";

    bool ok = true;

    // remove file
    {
        Remove rm;
        std::vector<std::string> cmd = {"remove", (temp / "sub" / "file.txt").string()};
        C2Message msg, ret;
        rm.init(cmd, msg);
        msg.set_cmd((temp / "sub" / "file.txt").string());
        rm.process(msg, ret);
        ok &= !fs::exists(temp / "sub" / "file.txt");
    }

    // remove directory
    {
        Remove rm;
        std::vector<std::string> cmd = {"remove", temp.string()};
        C2Message msg, ret;
        rm.init(cmd, msg);
        msg.set_cmd(temp.string());
        rm.process(msg, ret);
        ok &= !fs::exists(temp);
    }

    fs::remove_all(temp);
    return ok;
}
