#pragma once
#include <string>
#include <vector>
#include <sstream>

namespace tools::strings
{
	inline std::wstring to_wstring(const std::string& str)
	{
		int requiredSize = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
		if (requiredSize == 0)
		{
			// Handle error
			return L"";
		}

		std::wstring wstr(requiredSize - 1, '\0');
		int result = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], requiredSize);
		if (result == 0)
		{
			// Handle error
			return L"";
		}

		return wstr;
	}

	inline std::string to_string(const std::wstring& wstr)
	{
		int requiredSize = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
		if (requiredSize == 0)
		{
			// Handle error
			return "";
		}

		std::string str(requiredSize - 1, '\0');
		int result = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], requiredSize, NULL, NULL);
		if (result == 0)
		{
			// Handle error
			return "";
		}

		return str;
	}

	inline std::vector<std::string> split_string(const std::string& input, const char sep)
	{
		std::stringstream ss(input);
		std::string segment;
		std::vector<std::string> strings;

		while (std::getline(ss, segment, sep))
		{
			strings.push_back(segment);
		}

		return strings;
	}

	inline std::vector<std::wstring> split_string(const std::wstring& input, const wchar_t sep)
	{
		std::wstringstream wss(input);
		std::wstring segment;
		std::vector<std::wstring> strings;

		while (std::getline(wss, segment, sep))
		{
			strings.push_back(segment);
		}

		return strings;
	}
}
