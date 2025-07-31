#include "../Remove.hpp"
#include <filesystem>

bool testRemove();

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
    fs::path temp = fs::temp_directory_path() / "c2core_remove_test";
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
