#include "../Download.hpp"
#include <filesystem>
#include <fstream>

bool testDownload();

int main() {
    std::cout << "[+] testDownload" << std::endl;
    bool res = testDownload();
    if (res) {
        std::cout << "[+] Success" << std::endl;
    } else {
        std::cout << "[-] Failed" << std::endl;
    }
    return !res;
}

static bool filesEqual(const std::filesystem::path& a, const std::filesystem::path& b) {
    std::ifstream f1(a, std::ios::binary); 
    std::ifstream f2(b, std::ios::binary);
    std::string d1((std::istreambuf_iterator<char>(f1)), {});
    std::string d2((std::istreambuf_iterator<char>(f2)), {});
    return d1 == d2;
}

bool testDownload() {
    namespace fs = std::filesystem;
    fs::path temp = fs::temp_directory_path() / "c2core_download_test";
    fs::create_directories(temp);
    bool ok = true;

    // Small file
    {
        Download dl;
        fs::path src = temp / "src.txt";
        fs::path dst = temp / "dst.txt";
        std::string data = "small file";
        std::ofstream(src) << data;

        std::vector<std::string> cmd = {"download", src.string(), dst.string()};
        C2Message msg, ret;
        dl.init(cmd, msg);
        dl.process(msg, ret);
        dl.followUp(ret);
        std::cout << "small ret: " << ret.returnvalue() << " ec=" << ret.errorCode() << std::endl;
        bool sub = ret.errorCode() == -1 && ret.returnvalue() == "Success" && filesEqual(src, dst);
        std::cout << "small ok=" << sub << std::endl;
        ok &= sub;
    }

    // Large file requiring multiple chunks
    {
        Download dl;
        fs::path src = temp / "large.bin";
        fs::path dst = temp / "large_copy.bin";
        const size_t size = 1024 * 1024 + 500; // > CHUNK_SIZE
        std::string data(size, 'A');
        std::ofstream(src, std::ios::binary).write(data.data(), data.size());

        std::vector<std::string> cmd = {"download", src.string(), dst.string()};
        C2Message msg, ret; 
        dl.init(cmd, msg);
        dl.process(msg, ret);
        dl.followUp(ret);
        std::cout << "large first ret: " << ret.returnvalue() << " ec=" << ret.errorCode() << std::endl;
        while(ret.returnvalue() != "Success") {
            C2Message next;
            dl.recurringExec(next);
            dl.followUp(next);
            ret = next;
        }
        bool sub = filesEqual(src, dst);
        std::cout << "large ok=" << sub << std::endl;
        ok &= sub;
    }

    // Non-existent source file
    {
        Download dl;
        fs::path src = temp / "missing.txt";
        fs::path dst = temp / "missing_out.txt";
        std::vector<std::string> cmd = {"download", src.string(), dst.string()};
        C2Message msg, ret; 
        dl.init(cmd, msg);
        dl.process(msg, ret);
        dl.followUp(ret);
        std::cout << "missing ret: " << ret.returnvalue() << " ec=" << ret.errorCode() << std::endl;
        bool sub = ret.errorCode() != -1 && !fs::exists(dst);
        std::cout << "missing ok=" << sub << std::endl;
        ok &= sub;
    }

    fs::remove_all(temp);
    return ok;
}
