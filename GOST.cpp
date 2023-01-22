#include "GOST.h"
#include <cstdint>
#include <bitset>

namespace
{
const size_t BlockSize = sizeof(uint64_t);

const size_t Sbox[8][16] = {
	{  4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3 },
	{ 14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9 },
	{  5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11 },
	{  7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3 },
	{  6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2 },
	{  4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14 },
	{ 13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12 },
	{  1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12 }
};

void prepare_sub_keys(const char key[32], uint32_t subKeys[8])
{
	for (size_t i = 0; i < 8; ++i)
	{
		subKeys[i] |= *reinterpret_cast<uint32_t*>(const_cast<char*>(key + i));
	}
}

void read_block(const std::string& data, size_t offset, uint64_t& block)
{
	size_t position = offset * BlockSize;
	size_t remainder = std::min(data.length() - position, BlockSize);

	for (size_t i = 0; i < remainder; ++i)
	{
		block |= static_cast<uint64_t>(data[position + i]) << (56 - i * 8);
	}
}

uint32_t f(uint32_t subBlock, uint32_t subKey)
{
	subBlock += subKey;

	subBlock = (subBlock & 0x0fffffff) | (Sbox[7][(subBlock >> 28)] << 28);
	subBlock = (subBlock & 0xf0ffffff) | (Sbox[6][(subBlock & 0x0f000000) >> 24] << 24);
	subBlock = (subBlock & 0xff0fffff) | (Sbox[5][(subBlock & 0x00f00000) >> 20] << 20);
	subBlock = (subBlock & 0xfff0ffff) | (Sbox[4][(subBlock & 0x000f0000) >> 16] << 16);
	subBlock = (subBlock & 0xffff0fff) | (Sbox[3][(subBlock & 0x0000f000) >> 12] << 12);
	subBlock = (subBlock & 0xfffff0ff) | (Sbox[2][(subBlock & 0x00000f00) >> 8] << 8);
	subBlock = (subBlock & 0xffffff0f) | (Sbox[1][(subBlock & 0x000000f0) >> 4] << 4);
	subBlock = (subBlock & 0xfffffff0) | (Sbox[0][(subBlock & 0x0000000f)]);

	return subBlock;
}

void encode_sub_blocks(uint32_t subKeys[8], uint32_t& a, uint32_t& b)
{
	for (size_t i = 0; i < 23; i += 2)
	{
		a ^= f(b, subKeys[i % 8]);
		b ^= f(a, subKeys[(i + 1) % 8]);
	}

	for (size_t i = 24; i < 31; i += 2)
	{
		a ^= f(b, subKeys[31 - i]);
		b ^= f(a, subKeys[31 - (i + 1)]);
	}

	std::swap(a, b);
}

void encode_block(uint32_t subKeys[8], uint64_t& block)
{
	encode_sub_blocks(
		subKeys, 
		*reinterpret_cast<uint32_t*>(&block),
		*(reinterpret_cast<uint32_t*>(&block) + 1)
	);
}

size_t get_num_blocks(const size_t length)
{
	const size_t BlockAligner = BlockSize - 1;

	return ((length + BlockAligner) & ~BlockAligner) / BlockSize;
}

void write_block(uint64_t block, std::string& output)
{
	for (size_t i = 0; i < 8; ++i)
	{
		output.push_back(block >> (56 - i * 8) & 0xff);
	}
}
};

std::string GOST::encrypt(const char key[32], const std::string data)
{
	uint32_t subKeys[8];

	prepare_sub_keys(key, subKeys);

	size_t numBlocks = get_num_blocks(data.length());

	std::string cipher;
	cipher.reserve(numBlocks * 8);

	for (size_t i = 0; i < numBlocks; ++i)
	{
		uint64_t block = 0;

		read_block(data, i, block);
		encode_block(subKeys, block);
		write_block(block, cipher);
	}

	return cipher;
}