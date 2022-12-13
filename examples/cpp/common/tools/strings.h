#pragma once
#include <codecvt>
#include <locale>
#include <string>
#include <vector>
#include <sstream>

namespace tools::strings
{
	inline std::wstring to_wstring(const std::string& str)
	{
		using convert_type_x = std::codecvt_utf8<wchar_t>;
		std::wstring_convert<convert_type_x, wchar_t> converter_x;

		return converter_x.from_bytes(str);
	}

	inline std::string to_string(const std::wstring& str)
	{
		using convert_type_x = std::codecvt_utf8<wchar_t>;
		std::wstring_convert<convert_type_x, wchar_t> converter_x;

		return converter_x.to_bytes(str);
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
