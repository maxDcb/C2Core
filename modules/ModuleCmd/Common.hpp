#pragma once

#include <string>
#include <vector>
#include <random>
#include <string_view>


#include "spdlog/spdlog.h"

// TODO remplace!!!
#undef DEBUG_BUILD

#ifdef DEBUG_BUILD
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define DEBUG(x) do { std::cout << __FILENAME__ << " - " << __func__ << ": " << x << std::endl; } while (0)
#else
#define DEBUG(x) do {} while (0)
#endif


const int SizeListenerHash = 32;
const int SizeBeaconHash = 32;


constexpr unsigned long djb2(std::string_view str, unsigned long hash = 5381, std::size_t index = 0) 
{
    return (index == str.size()) ? hash : djb2(str, ((hash << 5) + hash) + str[index], index + 1);
}

template<std::size_t N, std::size_t M>
inline constexpr std::array<char, N> compileTimeXOR(const std::string_view data, const std::string_view key) 
{
    std::array<char, N> result{};
    std::size_t key_size = key.size();
    std::size_t j = 0;

    for (std::size_t i = 0; i < data.size(); ++i) {
        if (j == key_size) {
            j = 0;
        }

        result[i] = data[i] ^ key[j];
        ++j;
    }

    return result;
}


void static inline XOR(std::string& data, const std::string& key) 
{
	int j = 0;
	for (int i = 0; i < data.size(); i++) 
	{
		if (j == key.size()) 
			j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}


std::string static inline random_string(std::size_t length)
{
    const std::string CHARACTERS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    std::random_device random_device;
    std::mt19937 generator(random_device());
    std::uniform_int_distribution<> distribution(0, CHARACTERS.size() - 1);

    std::string random_string;
    for (std::size_t i = 0; i < length; ++i)
    {
        random_string += CHARACTERS[distribution(generator)];
    }

    return random_string;
}


bool static inline isNumber(const std::string& str)
{
	for (char const& c : str) {
		if (std::isdigit(c) == 0) return false;
	}
	return true;
}


void static inline splitList(std::string list, const std::string& delimiter, std::vector<std::string>& splitedList)
{
	size_t pos = 0;
	std::string token;
	while ((pos = list.find(delimiter)) != std::string::npos)
	{
		token = list.substr(0, pos);
		splitedList.push_back(token);
		list.erase(0, pos + delimiter.length());
	}
	splitedList.push_back(list);
}
