#include "../ChangeDirectory.hpp"

#include <filesystem>

bool testChangeDirectory();

int main()
{
    bool res;

    std::cout << "[+] testChangeDirectory" << std::endl;
    res = testChangeDirectory();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return !res;
}


bool testChangeDirectory()
{
    std::unique_ptr<ChangeDirectory> changeDirectory = std::make_unique<ChangeDirectory>();

    std::filesystem::path original = std::filesystem::current_path();
    std::filesystem::path temp = std::filesystem::temp_directory_path() / "c2core_change_dir_test";
    std::filesystem::create_directories(temp);
    std::cout << "original=" << original << " temp=" << temp << std::endl;

    // Change to temporary directory
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("cd");
        splitedCmd.push_back(temp.string());

        C2Message c2Message;
        C2Message c2RetMessage;
        changeDirectory->init(splitedCmd, c2Message);
        c2Message.set_cmd(temp.string());
        changeDirectory->process(c2Message, c2RetMessage);

        std::cout << "changed to: " << c2RetMessage.returnvalue() << std::endl;
        if (c2RetMessage.returnvalue() != temp.string()) {
            std::cout << "ret mismatch" << std::endl;
            return false;
        }
        if (std::filesystem::current_path() != temp) {
            std::cout << "cwd mismatch" << std::endl;
            return false;
        }
    }

    // Invalid directory should not change current path
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("cd");
        splitedCmd.push_back("does_not_exist");

        C2Message c2Message;
        C2Message c2RetMessage;
        changeDirectory->init(splitedCmd, c2Message);
        c2Message.set_cmd("does_not_exist");
        changeDirectory->process(c2Message, c2RetMessage);

        std::cout << "invalid result: " << c2RetMessage.returnvalue() << std::endl;
        if (c2RetMessage.returnvalue() != temp.string()) {
            std::cout << "invalid ret mismatch" << std::endl;
            return false;
        }
        if (std::filesystem::current_path() != temp) {
            std::cout << "invalid cwd mismatch" << std::endl;
            return false;
        }
    }

    // Return to original directory
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("cd");
        splitedCmd.push_back(original.string());

        C2Message c2Message;
        C2Message c2RetMessage;
        changeDirectory->init(splitedCmd, c2Message);
        c2Message.set_cmd(original.string());
        changeDirectory->process(c2Message, c2RetMessage);

        std::cout << "back result: " << c2RetMessage.returnvalue() << std::endl;
        if (c2RetMessage.returnvalue() != original.string()) {
            std::cout << "back ret mismatch" << std::endl;
            return false;
        }
        if (std::filesystem::current_path() != original) {
            std::cout << "back cwd mismatch" << std::endl;
            return false;
        }
    }

    std::filesystem::remove_all(temp);

    return true;
}
