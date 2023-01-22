#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "DES.h"
#include "GOST.h"

std::string hex(const std::string& str)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (size_t i = 0; str.length() > i; ++i)
    {
        ss << std::setw(2) << static_cast<uint32_t>(static_cast<uint8_t>(str[i]));
    }

    return ss.str();
}

int main()
{
    std::string data;
    {
        std::ifstream input("input.txt");
        std::stringstream buffer;
        buffer << input.rdbuf();
        data = buffer.str();
    }

    std::cout << "Input: " << std::endl;
    std::cout << data << std::endl;
    std::cout << std::endl;

    {
        const auto key = "HJfdbcj";

        std::string encrypted = DES::encrypt(key, data);
        std::ofstream output("output-des.txt", std::ios_base::binary);
        output << encrypted;

        std::cout << "DES (hex):" << std::endl;
        std::cout << hex(encrypted) << std::endl;
        std::cout << std::endl;
    }

    {
        const auto key = "aePZDKRQ9VmjsDeDUkJ9ZzPsgfpyvbh";

        std::string encrypted = GOST::encrypt(key, data);
        std::ofstream output("output-gost.txt", std::ios_base::binary);
        output << encrypted;

        std::cout << "GOST (hex): " << std::endl;
        std::cout << hex(encrypted) << std::endl;
        std::cout << std::endl;
    }

    std::cin.get();
}
