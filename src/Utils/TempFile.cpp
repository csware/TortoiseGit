﻿// TortoiseGit - a Windows shell extension for easy version control

// Copyright (C) 2009, 2011-2013, 2015-2016, 2018-2021, 2023, 2025 - TortoiseGit
// Copyright (C) 2003-2008, 2020 - TortoiseSVN

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
#include "TempFile.h"
#include "TGitPath.h"
#include "SmartHandle.h"
#include "Git.h"
#include "DirFileEnum.h"

CTempFiles::CTempFiles()
{
}

CTempFiles::~CTempFiles()
{
	m_TempFileList.DeleteAllFiles(false);
}

CTempFiles& CTempFiles::Instance()
{
	static CTempFiles instance;
	return instance;
}

CTGitPath CTempFiles::GetTempFilePath(bool bRemoveAtEnd, const CTGitPath& path /* = CTGitPath() */, const CGitHash& hash /* = CGitHash() */)
{
	DWORD len = GetTortoiseGitTempPath(0, nullptr);

	auto temppath = std::make_unique<wchar_t[]>(len + 1);
	auto tempF = std::make_unique<wchar_t[]>(len + 50);
	GetTortoiseGitTempPath(len + 1, temppath.get());
	CTGitPath tempfile;
	CString possibletempfile;
	if (path.IsEmpty())
	{
		::GetTempFileName (temppath.get(), L"git", 0, tempF.get());
		tempfile = CTGitPath(tempF.get());
	}
	else
	{
		int i=0;
		do
		{
			// use the UI path, which does unescaping for urls
			CString filename = path.GetBaseFilename();
			// remove illegal chars which could be present in urls
			filename.Remove('?');
			filename.Remove('*');
			filename.Remove('<');
			filename.Remove('>');
			filename.Remove('|');
			filename.Remove('"');
			// the inner loop assures that the resulting path is < MAX_PATH
			// if that's not possible without reducing the 'filename' to less than 5 chars, use a path
			// that's longer than MAX_PATH (in that case, we can't really do much to avoid longer paths)
			do
			{
				if (!hash.IsEmpty())
					possibletempfile.Format(L"%s%s-%s.%3.3x%s", temppath.get(), static_cast<LPCWSTR>(filename), static_cast<LPCWSTR>(hash.ToString(g_Git.GetShortHASHLength())), i, static_cast<LPCWSTR>(path.GetFileExtension()));
				else
					possibletempfile.Format(L"%s%s.%3.3x%s", temppath.get(), static_cast<LPCWSTR>(filename), i, static_cast<LPCWSTR>(path.GetFileExtension()));
				tempfile.SetFromWin(possibletempfile);
				filename.Truncate(std::max(0, filename.GetLength() - 1));
			} while (filename.GetLength() > 4 && tempfile.GetWinPathString().GetLength() >= MAX_PATH);
			++i;
			// now create the temp file in a thread safe way, so that subsequent calls to GetTempFile() return different filenames.
			CAutoFile hFile = CreateFile(tempfile.GetWinPath(), GENERIC_READ, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, nullptr);
			const auto lastErr = GetLastError();
			if (hFile || ((lastErr != ERROR_FILE_EXISTS) && (lastErr != ERROR_ACCESS_DENIED)))
				break;
		} while (true);
	}
	if (bRemoveAtEnd)
		m_TempFileList.AddPath(tempfile);
	return tempfile;
}

void CTempFiles::DeleteOldTempFiles()
{
	DWORD len = GetTortoiseGitTempPath(0, nullptr);
	auto path = std::make_unique<wchar_t[]>(len + 100);
	len = GetTortoiseGitTempPath (len + 100, path.get());
	if (len == 0)
		return;

	CDirFileEnum finder(path.get());
	FILETIME systime_;
	::GetSystemTimeAsFileTime(&systime_);
	const __int64 sysTime = static_cast<__int64>(systime_.dwHighDateTime) << 32 | systime_.dwLowDateTime;
	while (auto file = finder.NextFile())
	{
		CString filepath = file->GetFilePath();
		FILETIME createFileTime = file->GetCreateTime();
		__int64 createTime = static_cast<long long>(createFileTime.dwLowDateTime) | static_cast<long long>(createFileTime.dwHighDateTime) << 32LL;
		createTime += 864000000000LL; // only delete files older than a day
		if (createTime >= sysTime)
			continue;

		::SetFileAttributes(filepath, FILE_ATTRIBUTE_NORMAL);
		if (file->IsDirectory())
			::RemoveDirectory(filepath);
		else
			::DeleteFile(filepath);
	}
}
