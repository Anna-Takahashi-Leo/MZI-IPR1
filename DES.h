#pragma once

#include <string>

namespace DES
{
	std::string encrypt(const char key[8], const std::string data);
};
