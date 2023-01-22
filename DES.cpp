#include "DES.h"
#include <cstdint>
#include <bitset>

namespace
{
const size_t UserKeyBits = 64;
const size_t BaseKeyBits = 56;
const size_t HalfKeyBits = BaseKeyBits / 2;
const size_t SubKeyBits = 48;
const size_t SubKeyCount = 16;
const size_t BlockBits = 64;
const size_t BlockBytes = BlockBits / 8;
const size_t HalfBlockSize = BlockBits / 2;
const size_t ExpBlockSize = SubKeyBits;

using UserKey = std::bitset<UserKeyBits>;
using BaseKey = std::bitset<BaseKeyBits>;
using HalfKey = std::bitset<HalfKeyBits>;
using SubKey = std::bitset<SubKeyBits>;
using SubKeySet = SubKey[SubKeyCount];
using Block = std::bitset<BlockBits>;
using HalfBlock = std::bitset<HalfBlockSize>;
using ExpBlock = std::bitset<ExpBlockSize>;

const size_t KeyShifts[] = {
	1, 1, 2, 2, 2, 2, 2, 2, 
	1, 2, 2, 2, 2, 2, 2, 1,
};

const size_t PC_1[] = {
	57, 49, 41, 33, 25, 17, 9,
	1,  58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7,  62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4,
};

const size_t PC_2[] = {
	14, 17, 11, 24,  1,  5,
	3,  28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8,
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

const size_t IP[] = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9,  1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
};

const size_t IP_1[] = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41,  9, 49, 17, 57, 25,
};

const size_t E[] = {
	32,  1,  2,  3,  4,  5,
	 4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1,
};

const size_t Sbox[8][4][16] = {
	{
		{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
		{ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
		{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
		{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
	},
	{
		{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
		{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
		{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
		{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
	},
	{
		{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
		{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
		{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
		{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
	},
	{
		{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
		{ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
		{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
		{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
	},
	{
		{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
		{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
		{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
		{ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
	},
	{
		{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
		{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
		{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
		{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
	},
	{
		{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
		{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
		{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
		{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
	},
	{
		{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
		{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
		{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
		{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 },
	},
};

const size_t Pbox[] = {
	16,  7, 20, 21,
	29, 12, 28, 17,
	1,  15, 23, 26,
	5,  18, 31, 10,
	2,   8, 24, 14,
	32, 27,  3,  9,
	19, 13, 30,  6,
	22, 11,  4, 25,
};

void read_user_key(const char key[8], UserKey& userKey)
{
	uint64_t value = 0;

	for (size_t i = 0; i < 8; ++i)
	{
		value |= static_cast<uint64_t>(key[i]) << (56 - i * 8);
	}

	userKey = UserKey(value);
}

void rotate_half_key(HalfKey& half, size_t shift)
{
	half = half << shift | half >> (HalfKeyBits - shift);
}

void generare_sub_keys(UserKey userKey, SubKeySet& subKeys)
{
	BaseKey baseKey;
	HalfKey left;
	HalfKey right;
	SubKey subKey;

	for (int i = 0; i < BaseKeyBits; ++i)
	{
		baseKey[BaseKeyBits - 1 - i] = userKey[UserKeyBits - PC_1[i]];
	}

	for (int i = 0; i < HalfKeyBits; ++i)
	{
		left[i] = baseKey[i + HalfKeyBits];
		right[i] = baseKey[i];
	}

	for (int round = 0; round < SubKeyCount; ++round)
	{
		rotate_half_key(left, KeyShifts[round]);
		rotate_half_key(right, KeyShifts[round]);

		for (int i = 0; i < HalfKeyBits; ++i)
		{
			baseKey[i + HalfKeyBits] = left[i];
			baseKey[i] = right[i];
		}

		for (int i = 0; i < SubKeyBits; ++i)
		{
			subKey[SubKeyBits - 1 - i] = baseKey[BaseKeyBits - PC_2[i]];
		}

		subKeys[round] = subKey;
	}
}

void read_block(const std::string& data, size_t offset, Block& output)
{
	uint64_t value = 0;
	size_t position = offset * BlockBytes;
	size_t remainder = std::min(data.length() - position, BlockBytes);

	for (size_t i = 0; i < remainder; ++i)
	{
		value |= static_cast<uint64_t>(data[position + i]) << (BlockBits - 8 - i * 8);
	}

	output = Block(value);
}

void permutate_init_block(Block input, Block& output)
{
	for (int i = 0; i < BlockBits; ++i)
	{
		output[i] = input[IP[i] - 1];
	}
}

void divide_block(Block input, HalfBlock& left, HalfBlock& right)
{
	for (int i = 0; i < HalfBlockSize; ++i)
	{
		left[i] = input[i + HalfBlockSize];
		right[i] = input[i];
	}
}

void expand_block(HalfBlock input, ExpBlock& output)
{
	for (int i = 0; i < ExpBlockSize; ++i)
	{
		output[i] = input[E[i] - 1];
	}
}

void mix_block_with_key(SubKey subKey, ExpBlock& output)
{
	output ^= subKey;
}

void substitute_with_sbox(ExpBlock input, HalfBlock& output)
{
	size_t x = 0;

	for (size_t i = 0; i < ExpBlockSize; i += 6)
	{
		size_t row = input[ExpBlockSize - 1 - i] * 2
			+ input[ExpBlockSize - 1 - i - 5];

		size_t col = input[ExpBlockSize - 1 - i - 1] * 8
			+ input[ExpBlockSize - 1 - i - 2] * 4
			+ input[ExpBlockSize - 1 - i - 3] * 2
			+ input[ExpBlockSize - 1 - i - 4];

		std::bitset<4> s(Sbox[i / 6][row][col]);

		output[HalfBlockSize - 1 - x] = s[3];
		output[HalfBlockSize - 1 - x - 1] = s[2];
		output[HalfBlockSize - 1 - x - 2] = s[1];
		output[HalfBlockSize - 1 - x - 3] = s[0];

		x += 4;
	}
}

void permutate_with_pbox(HalfBlock input, HalfBlock& output)
{
	for (int i = 0; i < HalfBlockSize; ++i)
	{
		output[HalfBlockSize - 1 - i] = input[HalfBlockSize - Pbox[i]];
	}
}

HalfBlock feistel(HalfBlock input, SubKey subKey)
{
	ExpBlock expanded;
	HalfBlock substituted;
	HalfBlock result;

	expand_block(input, expanded);
	mix_block_with_key(subKey, expanded);
	substitute_with_sbox(expanded, substituted);
	permutate_with_pbox(substituted, result);

	return result;
}

void apply_feistel(SubKeySet subKeys, HalfBlock& left, HalfBlock& right)
{
	for (int round = 0; round < SubKeyCount; ++round)
	{
		HalfBlock temp = right;
		right = left ^ feistel(right, subKeys[round]);
		left = temp;
	}
}

void concat_block(HalfBlock left, HalfBlock right, Block& output)
{
	for (int i = 0; i < HalfBlockSize; ++i)
	{
		output[i + HalfBlockSize] = left[i];
		output[i] = right[i];
	}
}

void permutate_final_block(Block input, Block& output)
{
	for (int i = 0; i < BlockBits; ++i)
	{
		output[BlockBits - 1 - i] = input[BlockBits - IP_1[i]];
	}
}

void encode_block(Block input, SubKeySet subKeys, Block& output)
{
	Block block;
	HalfBlock left;
	HalfBlock right;

	permutate_init_block(input, block);
	divide_block(block, left, right);
	apply_feistel(subKeys, left, right);
	concat_block(right, left, block);
	permutate_final_block(block, output);
}

size_t get_num_blocks(const size_t length)
{
	const size_t BlockAligner = BlockBytes - 1;

	return ((length + BlockAligner) & ~BlockAligner) / BlockBytes;
}

void write_block(Block block, std::string& output)
{
	uint64_t value = block.to_ullong();

	for (size_t i = 0; i < 8; ++i)
	{
		output.push_back(value >> (BlockBits - 8 - i * 8) & 0xff);
	}
}
};

std::string DES::encrypt(const char key[8], const std::string data)
{
	UserKey userKey;
	SubKeySet subKeys;
	
	read_user_key(key, userKey);
	generare_sub_keys(userKey, subKeys);

	size_t numBlocks = get_num_blocks(data.length());

	std::string cipher;
	cipher.reserve(numBlocks * 8);

	for (size_t i = 0; i < numBlocks; ++i)
	{
		Block input;
		Block output;

		read_block(data, i, input);
		encode_block(input, subKeys, output);
		write_block(output, cipher);
	}
	
	return cipher;
}
