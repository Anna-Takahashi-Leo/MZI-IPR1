#pragma once

#include <string>

namespace GOST
{
	std::string encrypt(const char key[32], const std::string data);
};
