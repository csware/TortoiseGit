// TortoiseGit - a Windows shell extension for easy version control

// Copyright (C) 2016 - TortoiseGit

// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//

#include "stdafx.h"
#include "StringUtils.h"
#include "..\..\ext\simpleini\SimpleIni.h"

static const wchar_t *escapes = L"ntb\"\\";
static const wchar_t *escaped = L"\n\t\b\"\\";
static CString GetConfigValue(const wchar_t* ptr)
{
	if (!ptr)
		return L"";

	CString value;
	{
		CStrBuf working(value, (int)min(wcslen(ptr), INT_MAX - 1));
		wchar_t* fixed = working;
		bool quoted = false;

		while (*ptr) {
			if (*ptr == L'"')
				quoted = !quoted;
			else if (*ptr != L'\\')
			{
				if (!quoted && (*ptr == L'#' || *ptr == L';'))
					break;
				*fixed++ = *ptr;
			}
			else
			{
				/* backslash, check the next char */
				++ptr;
				const wchar_t* esc = wcschr(escapes, *ptr);
				if (esc)
					*fixed++ = escaped[esc - escapes];
				else
					return L"";
			}
			++ptr;
		}
		*fixed = L'\0';
	}

	return value;
}

TEST(versiontxt, parseagainstlibgit2)
{
	CString fn = GetCommandLine();
	int first = fn.Find(_T(' '));
	if (first > 0) {
		fn = fn.Mid(first).Trim(L"\"").Trim();
	}
	_wprintf_p(L"\n\"%s\"\n", fn);

	CAutoConfig versioncheck(true);
	ASSERT_EQ(0, git_config_add_file_ondisk(versioncheck, CUnicodeUtils::GetUTF8(fn), GIT_CONFIG_LEVEL_GLOBAL, 0));

	CSimpleIni versioncheckSI(true, true);
	ASSERT_EQ(SI_OK, versioncheckSI.LoadFile(fn));

	for (const CString& entry : { L"version", L"versionstring", L"infotext", L"infotexturl", L"baseurl", L"mainfilename", L"languagepackfilename", L"issuesurl", L"changelogurl" })
	{
		CString value;
		versioncheck.GetString(L"tortoisegit." + entry, value);
		EXPECT_STREQ(value, GetConfigValue(versioncheckSI.GetValue(L"tortoisegit", entry)));
	}

	std::vector<CString> langs;
	git_config_get_multivar_foreach(versioncheck, "tortoisegit.langs", nullptr, [](const git_config_entry* configentry, void* payload) -> int
	{
		auto langs = reinterpret_cast<std::vector<CString>*>(payload);
		langs->push_back(configentry->value);
		return 0;
	}, &langs);

	CSimpleIni::TNamesDepend values;
	versioncheckSI.GetAllValues(L"tortoisegit", L"langs", values);
	ASSERT_EQ(langs.size(), values.size());
	size_t i = 0;
	for (const auto& value : values)
	{
		EXPECT_STREQ(langs[i], GetConfigValue(value.pItem));
		++i;
	}
}
