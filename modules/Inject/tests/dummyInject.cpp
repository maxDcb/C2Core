#include <chrono>
#include <cstring>
#include <iostream>
#include <fstream>
#include <thread>

int main(int argc, char** argv)
{
    if (argc > 1 && std::strcmp(argv[1], "--sleep") == 0)
    {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        return 0;
    }

    for (int i = 1; i + 1 < argc; ++i)
    {
        if (std::strcmp(argv[i], "--marker") == 0)
        {
            std::ofstream marker(argv[i + 1], std::ios::binary);
            marker << "inject-dummy";
            if (!marker)
                return 1;
        }
    }

    std::cout << "inject-dummy";
    for (int i = 1; i < argc; ++i)
    {
        std::cout << ' ' << argv[i];
    }
    std::cout << std::endl;
    return 0;
}
