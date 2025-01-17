#include <iostream>
#include <thread>


int main()
{
    for(int i = 0; i<10 ; i++)
    {
        for(int j = 0; j<400 ; j++)
        {
            std::cout << char(41)+i;
        }
        std::cout << std::endl;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cout << "" << std::endl;

    for(int j = 0; j<4000 ; j++)
    {
        std::cout << "ZO";
    }
    for(int j = 0; j<4000 ; j++)
    {
        std::cout << "ZA";
    }
    std::cout << std::endl;
}