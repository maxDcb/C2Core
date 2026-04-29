#include "../Tree.hpp"

#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <thread>

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

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
    fs::path temp = uniqueTestTempPath("c2core_tree_test");
    fs::remove_all(temp);
    fs::create_directories(temp / "sub");
    std::ofstream(temp / "file.txt") << "data";
    std::ofstream(temp / "sub" / "inner.txt") << "data";

    std::unique_ptr<Tree> tree = std::make_unique<Tree>();
    bool ok = true;

    // ----- explicit path -----
    {
        std::vector<std::string> cmd = {"tree", temp.string()};
        C2Message msg, ret;
        tree->init(cmd, msg);
        msg.set_cmd(temp.string());
        tree->process(msg, ret);
        std::string out = ret.returnvalue();
        ok &= out.find((temp / "file.txt").string()) != std::string::npos;
        ok &= out.find((temp / "sub").string() + "\\") != std::string::npos;
    }

    // ----- path with spaces using split tokens -----
    fs::path spacedDir = temp / "dir space";
    fs::create_directories(spacedDir);
    std::ofstream(spacedDir / "dummy.txt") << "a";
    {
        std::vector<std::string> cmd = {"tree", (temp.string()+"/dir").c_str(), "space"};
        C2Message msg, ret;
        tree->init(cmd, msg);
        msg.set_cmd(spacedDir.string());
        tree->process(msg, ret);
        ok &= ret.returnvalue().find((spacedDir/"dummy.txt").string()) != std::string::npos;
    }

    // ----- invalid path -----
    {
        fs::path invalid = temp / "does_not_exist";
        std::vector<std::string> cmd = {"tree", invalid.string()};
        C2Message msg, ret;
        tree->init(cmd, msg);
        msg.set_cmd(invalid.string());
        tree->process(msg, ret);
        ok &= ret.returnvalue().empty();
    }

    // ----- no argument -----
    {
        std::vector<std::string> cmd = {"tree"};
        C2Message msg, ret;
        tree->init(cmd, msg);
        tree->process(msg, ret);
        ok &= !ret.returnvalue().empty();
    }

    fs::remove_all(temp);
    return ok;
}
