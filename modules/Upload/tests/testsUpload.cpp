#include "../Upload.hpp"
#include <filesystem>
#include <fstream>

bool testUpload();

int main() {
    std::cout << "[+] testUpload" << std::endl;
    bool res = testUpload();
    if (res) {
        std::cout << "[+] Success" << std::endl;
    } else {
        std::cout << "[-] Failed" << std::endl;
    }
    return !res;
}

static bool fileContentEqual(const std::filesystem::path& p, const std::string& expected) {
    std::ifstream f(p, std::ios::binary);
    if(!f) return false;
    std::string data((std::istreambuf_iterator<char>(f)), {});
    return data == expected;
}

bool testUpload() {
    namespace fs = std::filesystem;
    fs::path temp = fs::temp_directory_path() / "c2core_upload_test";
    fs::create_directories(temp);
    bool ok = true;

    // Successful upload
    {
        Upload up;
        std::string content = "upload_test";
        fs::path src = temp / "src.txt";
        fs::path dst = temp / "dst.txt";
        std::ofstream(src) << content;

        std::vector<std::string> cmd = {"upload", src.string(), dst.string()};
        C2Message msg, ret;
        up.init(cmd, msg);
        up.process(msg, ret);
        std::cout << "success ret=" << ret.returnvalue() << " ec=" << ret.errorCode() << std::endl;
        bool sub = ret.errorCode() == -1 && ret.returnvalue() == "Success." && fileContentEqual(dst, content);
        std::cout << "success ok=" << sub << std::endl;
        ok &= sub;
    }

    // Invalid destination path
    {
        Upload up;
        std::string content = "test";
        fs::path src = temp / "src2.txt";
        fs::path dst = temp / "dir_not_exist" / "file.txt";
        std::ofstream(src) << content;

        std::vector<std::string> cmd = {"upload", src.string(), dst.string()};
        C2Message msg, ret;
        up.init(cmd, msg);
        up.process(msg, ret);
        std::cout << "bad dest ret=" << ret.returnvalue() << " ec=" << ret.errorCode() << std::endl;
        bool sub = ret.errorCode() != -1 && !fs::exists(dst);
        std::cout << "bad dest ok=" << sub << std::endl;
        ok &= sub;
    }

    // Missing source file
    {
        Upload up;
        fs::path src = temp / "no_file.txt";
        fs::path dst = temp / "out.txt";
        std::vector<std::string> cmd = {"upload", src.string(), dst.string()};
        C2Message msg;
        int r = up.init(cmd, msg);
        bool sub = r != 0 && msg.returnvalue().find("Couldn't open file") != std::string::npos;
        std::cout << "missing ok=" << sub << std::endl;
        ok &= sub;
    }

    fs::remove_all(temp);
    return ok;
}
