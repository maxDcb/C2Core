#include "../Cat.hpp"

#include <filesystem>

#ifdef __linux__
#elif _WIN32
#include <windows.h>
#endif

bool testCat();

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
    fs::path temp = fs::temp_directory_path() / "c2core_cat_test";
    fs::create_directories(temp);

    bool ok = true;

    std::unique_ptr<Cat> cat = std::make_unique<Cat>();

    // ----- valid file -----
    fs::path file = temp / "file.txt";
    {
        std::ofstream(file) << "hello";
        std::vector<std::string> cmd = {"cat", file.string()};
        C2Message msg, ret;
        cat->init(cmd, msg);
        msg.set_inputfile(file.string());
        cat->process(msg, ret);
        
        ok &= ret.returnvalue().find("hello") == 0;
    }

    // ----- path containing spaces and tokens splitted -----
    fs::path spaced = temp / "space file.txt";
    {
        std::ofstream(spaced) << "space";
        std::vector<std::string> cmd = {"cat", (temp.string()+"/space").c_str(), "file.txt"};
        C2Message msg, ret;
        cat->init(cmd, msg);
        msg.set_inputfile(spaced.string());
        cat->process(msg, ret);

        ok &= ret.returnvalue().find("space") == 0;
    }

    // ----- invalid file -----
    {
        fs::path invalid = temp / "does_not_exist.txt";
        std::vector<std::string> cmd = {"cat", invalid.string()};
        C2Message msg, ret;
        cat->init(cmd, msg);
        msg.set_inputfile(invalid.string());
        cat->process(msg, ret);
        std::string err;
        cat->errorCodeToMsg(ret, err);
#ifdef BUILD_TEAMSERVER
        ok &= ret.errorCode() == 1 && !err.empty();
#else

        ok &= ret.errorCode() == 1;
#endif
    }



    fs::remove_all(temp);
    return ok;
}
