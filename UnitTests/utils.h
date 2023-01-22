#pragma once
#include <iomanip>
#include <sstream>


inline std::string as_hex(const std::string& str)
{
	std::stringstream ss;
	ss << std::hex << std::setfill('0');

	for (size_t i = 0; str.length() > i; ++i)
	{
		ss << std::setw(2) << static_cast<uint32_t>(static_cast<uint8_t>(str[i]));
	}

	return ss.str();
}
