#include "../ListDirectory.hpp"

#include <filesystem>
#include <fstream>

bool testListDirectory();

int main()
{
    bool res;

    std::cout << "[+] testListDirectory" << std::endl;
    res = testListDirectory();
    if (res)
       std::cout << "[+] Sucess" << std::endl;
    else
       std::cout << "[-] Failed" << std::endl;

    return !res;
}

bool testListDirectory()
{
    std::unique_ptr<ListDirectory> listDirectory = std::make_unique<ListDirectory>();

    // Prepare temporary directory with a file
    std::filesystem::path temp = std::filesystem::temp_directory_path() / "c2core_listdir_test";
    std::filesystem::create_directories(temp);
    std::ofstream(temp / "file.txt") << "data";

    bool ok = true;

    // List temporary directory and expect file name in output
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("ls");
        splitedCmd.push_back(temp.string());

        C2Message c2Message;
        C2Message c2RetMessage;
        listDirectory->init(splitedCmd, c2Message);
        c2Message.set_cmd(temp.string());
        listDirectory->process(c2Message, c2RetMessage);
        std::cout << "list result: \n" << c2RetMessage.returnvalue() << std::endl;
        if (c2RetMessage.returnvalue().find("file.txt") == std::string::npos) {
            std::cout << "no file" << std::endl;
            ok = false;
        }
    }

    // Invalid directory should contain error
    {
        std::vector<std::string> splitedCmd;
        splitedCmd.push_back("ls");
        splitedCmd.push_back((temp / "does_not_exist").string());

        C2Message c2Message;
        C2Message c2RetMessage;
        listDirectory->init(splitedCmd, c2Message);
        std::string invalidPath = (temp / "does_not_exist").string();
        c2Message.set_cmd(invalidPath);
        listDirectory->process(c2Message, c2RetMessage);
        std::cout << "invalid result: \n" << c2RetMessage.returnvalue() << std::endl;
        if (c2RetMessage.returnvalue() != invalidPath + ":\n") {
            ok = false;
        }
    }

    std::filesystem::remove_all(temp);

    return ok;
}
