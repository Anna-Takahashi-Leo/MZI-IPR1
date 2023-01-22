#include "pch.h"
#include "CppUnitTest.h"
#include "../DES.h"
#include "../GOST.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTests
{
	TEST_CLASS(UnitTests)
	{
	public:
		
		TEST_METHOD(TestDES)
		{
			std::string key = "01234567";
			std::string data = "Test Data";
			std::string encrypted = DES::encrypt(key.c_str(), data);

			Assert::IsTrue(as_hex(encrypted) == "ac77741a613a8dda2a0bd4d88a3cfb55");
		}

		TEST_METHOD(TestGOST)
		{
			std::string key = "01234567890123456789012345678901";
			std::string data = "Test Data";
			std::string encrypted = GOST::encrypt(key.c_str(), data);

			Assert::IsTrue(as_hex(encrypted) == "2eae709f65197b797470ce8781994240");
		}
	};
}
