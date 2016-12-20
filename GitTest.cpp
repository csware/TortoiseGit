// TortoiseGit - a Windows shell extension for easy version control

// Copyright (C) 2015-2016 - TortoiseGit

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

TEST(ZZZ, LongPath)
{
	CAutoFile handle = CreateFileW(L"\\\\?\\D:\\TortoiseGit\\src\\Changelog.txt", 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	EXPECT_TRUE(handle.IsValid());
	CAutoFile handle1 = CreateFileW(L"\\\\?\\D:\\TortoiseGit\\src/Changelog.txt", 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	EXPECT_FALSE(handle1.IsValid());
	CAutoFile handle2 = CreateFileW(L"\\\\?\\D:\\TortoiseGit\\src", 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	EXPECT_TRUE(handle2.IsValid());
	CAutoFile handle3 = CreateFileW(L"\\\\?\\D:\\TortoiseGit\\src\\..\\build.txt", 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	EXPECT_FALSE(handle3.IsValid());
	CAutoFile handle4 = CreateFileW(L"\\\\?\\D:\\", 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	EXPECT_TRUE(handle4.IsValid());
	CAutoFile handle5 = CreateFileW(L"\\\\?\\D:\\TortoiseGit\\notexi", 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	EXPECT_FALSE(handle5.IsValid());
	CAutoFile handle6 = CreateFileW(L"\\\\?\\D:\\Tortoisgit", 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	EXPECT_FALSE(handle6.IsValid());
	CAutoFile handle7 = CreateFileW(L"\\\\?\\D:\\TortoiseGit\\src\\", 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	EXPECT_TRUE(handle7.IsValid());
}

TEST(ZZZ, LongPath2)
{
	static const int MAX_LONG_PATH = 4096;
	CString buf;
	EXPECT_NE(0, GetFullPathNameW(L"\\\\?\\D:\\TortoiseGit\\src/Changelog.txt", MAX_LONG_PATH, CStrBuf(buf, MAX_LONG_PATH), nullptr));
	EXPECT_STREQ(L"\\\\?\\D:\\TortoiseGit\\src\\Changelog.txt", buf);
	buf.Empty();
	EXPECT_NE(0, GetFullPathNameW(L"\\\\?\\D:\\TortoiseGit\\src\\..\\build.txt", MAX_LONG_PATH, CStrBuf(buf, MAX_LONG_PATH), nullptr));
	EXPECT_STREQ(L"\\\\?\\D:\\TortoiseGit\\build.txt", buf);
	buf.Empty();
	EXPECT_NE(0, GetFullPathNameW(L"\\\\?\\D:\\TortoiseGit\\src\\..\\..\\build.txt", MAX_LONG_PATH, CStrBuf(buf, MAX_LONG_PATH), nullptr));
	EXPECT_STREQ(L"\\\\?\\D:\\build.txt", buf);
	buf.Empty();
	EXPECT_NE(0, GetFullPathNameW(L"tests.exe", MAX_LONG_PATH, CStrBuf(buf, MAX_LONG_PATH), nullptr));
	EXPECT_STREQ(L"wieschautdasaus?", buf);
	/*buf.Empty();
	EXPECT_EQ(0, GetFullPathNameW(L"\\\\?\\D:\\TortoiseGit\\src\\..\\..\\..\\build.txt", MAX_LONG_PATH, CStrBuf(buf, MAX_LONG_PATH), nullptr));
	EXPECT_STREQ(L"", buf);*/
}

TEST(ZZZ, GetCurrentDirectoryW)
{
	EXPECT_EQ(0, GetCurrentDirectoryW(0, nullptr));

	static const int MAX_LONG_PATH = 4096;
	CString buf;
	EXPECT_NE(0, GetCurrentDirectoryW(MAX_LONG_PATH, CStrBuf(buf, MAX_LONG_PATH)));
	// contains 8.3 format path
	CString buf2;
	EXPECT_NE(0, GetFullPathNameW(buf, MAX_LONG_PATH, CStrBuf(buf2, MAX_LONG_PATH), nullptr));
	EXPECT_STREQ(L"GetFullPathNameW for GetCurrentDirectoryW", buf2);
	buf2.Empty();
	EXPECT_NE(0, GetFullPathNameW(L"\\\\?\\" + buf, MAX_LONG_PATH, CStrBuf(buf2, MAX_LONG_PATH), nullptr));
	EXPECT_STREQ(L"hier sollte es passen", buf2);
	// git for windows uses here the following approach:
	// createfile om this
	// GetFinalPathNameByHandleW -> get \\?\ path
}

#if 0
static inline void convert_slashes(char *path)
{
	for (; *path; path++)
		if (*path == '\\')
			*path = '/';
}

/**
* Max length of long paths (exceeding MAX_PATH). The actual maximum supported
* by NTFS is 32,767 (* sizeof(wchar_t)), but we choose an arbitrary smaller
* value to limit required stack memory.
*/
#define MAX_LONG_PATH 4096

/**
* Handles paths that would exceed the MAX_PATH limit of Windows Unicode APIs.
*
* With expand == false, the function checks for over-long paths and fails
* with ENAMETOOLONG. The path parameter is not modified, except if cwd + path
* exceeds max_path, but the resulting absolute path doesn't (e.g. due to
* eliminating '..' components). The path parameter must point to a buffer
* of max_path wide characters.
*
* With expand == true, an over-long path is automatically converted in place
* to an absolute path prefixed with '\\?\', and the new length is returned.
* The path parameter must point to a buffer of MAX_LONG_PATH wide characters.
*
* Parameters:
* path: path to check and / or convert
* len: size of path on input (number of wide chars without \0)
* max_path: max short path length to check (usually MAX_PATH = 260, but just
* 248 for CreateDirectoryW)
* expand: false to only check the length, true to expand the path to a
* '\\?\'-prefixed absolute path
*
* Return:
* length of the resulting path, or -1 on failure
*
* Errors:
* ENAMETOOLONG if path is too long
*/
int handle_long_path(wchar_t *path, int len, int max_path, int expand);

/**
* Converts UTF-8 encoded string to UTF-16LE.
*
* To support repositories with legacy-encoded file names, invalid UTF-8 bytes
* 0xa0 - 0xff are converted to corresponding printable Unicode chars \u00a0 -
* \u00ff, and invalid UTF-8 bytes 0x80 - 0x9f (which would make non-printable
* Unicode) are converted to hex-code.
*
* Lead-bytes not followed by an appropriate number of trail-bytes, over-long
* encodings and 4-byte encodings > \u10ffff are detected as invalid UTF-8.
*
* Maximum space requirement for the target buffer is two wide chars per UTF-8
* char (((strlen(utf) * 2) + 1) [* sizeof(wchar_t)]).
*
* The maximum space is needed only if the entire input string consists of
* invalid UTF-8 bytes in range 0x80-0x9f, as per the following table:
*
*               |                   | UTF-8 | UTF-16 |
*   Code point  |  UTF-8 sequence   | bytes | words  | ratio
* --------------+-------------------+-------+--------+-------
* 000000-00007f | 0-7f              |   1   |   1    |  1
* 000080-0007ff | c2-df + 80-bf     |   2   |   1    |  0.5
* 000800-00ffff | e0-ef + 2 * 80-bf |   3   |   1    |  0.33
* 010000-10ffff | f0-f4 + 3 * 80-bf |   4   |  2 (a) |  0.5
* invalid       | 80-9f             |   1   |  2 (b) |  2
* invalid       | a0-ff             |   1   |   1    |  1
*
* (a) encoded as UTF-16 surrogate pair
* (b) encoded as two hex digits
*
* Note that, while the UTF-8 encoding scheme can be extended to 5-byte, 6-byte
* or even indefinite-byte sequences, the largest valid code point \u10ffff
* encodes as only 4 UTF-8 bytes.
*
* Parameters:
* wcs: wide char target buffer
* utf: string to convert
* wcslen: size of target buffer (in wchar_t's)
* utflen: size of string to convert, or -1 if 0-terminated
*
* Returns:
* length of converted string (_wcslen(wcs)), or -1 on failure
*
* Errors:
* EINVAL: one of the input parameters is invalid (e.g. NULL)
* ERANGE: the output buffer is too small
*/
int xutftowcsn(wchar_t *wcs, const char *utf, size_t wcslen, int utflen);

/**
* Simplified variant of xutftowcsn, assumes input string is \0-terminated.
*/
static inline int xutftowcs(wchar_t *wcs, const char *utf, size_t wcslen)
{
	return xutftowcsn(wcs, utf, wcslen, -1);
}

/**
* Simplified file system specific wrapper of xutftowcsn and handle_long_path.
* Converts ERANGE to ENAMETOOLONG. If expand is true, wcs must be at least
* MAX_LONG_PATH wide chars (see handle_long_path).
*/
static inline int xutftowcs_path_ex(wchar_t *wcs, const char *utf,
	size_t wcslen, int utflen, int max_path, int expand)
{
	int result = xutftowcsn(wcs, utf, wcslen, utflen);
	if (result < 0 && errno == ERANGE)
		errno = ENAMETOOLONG;
	if (result >= 0)
		result = handle_long_path(wcs, result, max_path, expand);
	return result;
}

/**
* Simplified file system specific variant of xutftowcsn, assumes output
* buffer size is MAX_PATH wide chars and input string is \0-terminated,
* fails with ENAMETOOLONG if input string is too long. Typically used for
* Windows APIs that don't support long paths, e.g. SetCurrentDirectory,
* LoadLibrary, CreateProcess...
*/
static inline int xutftowcs_path(wchar_t *wcs, const char *utf)
{
	return xutftowcs_path_ex(wcs, utf, MAX_PATH, -1, MAX_PATH, 0);
}

/**
* Simplified file system specific variant of xutftowcsn for Windows APIs
* that support long paths via '\\?\'-prefix, assumes output buffer size is
* MAX_LONG_PATH wide chars, fails with ENAMETOOLONG if input string is too
* long. The 'core.longpaths' git-config option controls whether the path
* is only checked or expanded to a long path.
*/
static inline int xutftowcs_long_path(wchar_t *wcs, const char *utf)
{
	return xutftowcs_path_ex(wcs, utf, MAX_LONG_PATH, -1, MAX_PATH,
		core_long_paths);
}

/* Normalizes NT paths as returned by some low-level APIs. */
static wchar_t *normalize_ntpath(wchar_t *wbuf)
{
	int i;
	/* fix absolute path prefixes */
	if (wbuf[0] == '\\')
	{
		/* strip NT namespace prefixes */
		if (!wcsncmp(wbuf, L"\\??\\", 4) ||
			!wcsncmp(wbuf, L"\\\\?\\", 4))
			wbuf += 4;
		else if (!wcsnicmp(wbuf, L"\\DosDevices\\", 12))
			wbuf += 12;
		/* replace remaining '...UNC\' with '\\' */
		if (!wcsnicmp(wbuf, L"UNC\\", 4))
		{
			wbuf += 2;
			*wbuf = '\\';
		}
	}
	/* convert backslashes to slashes */
	for (i = 0; wbuf[i]; i++)
		if (wbuf[i] == '\\')
			wbuf[i] = '/';
	return wbuf;
}

char *mingw_getcwd(char *pointer, int len)
{
	wchar_t cwd[MAX_PATH], wpointer[MAX_PATH];
	DECLARE_PROC_ADDR(kernel32.dll, DWORD, GetFinalPathNameByHandleW,
	HANDLE, LPWSTR, DWORD, DWORD);
	DWORD ret = GetCurrentDirectoryW(ARRAY_SIZE(cwd), cwd);

	if (ret < 0 || ret >= ARRAY_SIZE(cwd))
		return NULL;
	ret = GetLongPathNameW(cwd, wpointer, ARRAY_SIZE(wpointer));
	if (!ret && GetLastError() == ERROR_ACCESS_DENIED &&
		INIT_PROC_ADDR(GetFinalPathNameByHandleW))
	{
		HANDLE hnd = CreateFileW(cwd, 0,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
			OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
		if (hnd == INVALID_HANDLE_VALUE)
			return NULL;
		ret = GetFinalPathNameByHandleW(hnd, wpointer, ARRAY_SIZE(wpointer), 0);
		CloseHandle(hnd);
		if (!ret || ret >= ARRAY_SIZE(wpointer))
			return NULL;
		if (xwcstoutf(pointer, normalize_ntpath(wpointer), len) < 0)
			return NULL;
		return pointer;
	}
	if (!ret || ret >= ARRAY_SIZE(wpointer))
		return NULL;
	if (xwcstoutf(pointer, wpointer, len) < 0)
		return NULL;
	convert_slashes(pointer);
	return pointer;
}

int handle_long_path(wchar_t *path, int len, int max_path, int expand)
{
	int result;
	wchar_t buf[MAX_LONG_PATH];

	/*
	* we don't need special handling if path is relative to the current
	* directory, and current directory + path don't exceed the desired
	* max_path limit. This should cover > 99 % of cases with minimal
	* performance impact (git almost always uses relative paths).
	*/
	if ((len < 2 || (!is_dir_sep(path[0]) && path[1] != ':')) &&
		(current_directory_len + len < max_path))
		return len;

	/*
	* handle everything else:
	* - absolute paths: "C:\dir\file"
	* - absolute UNC paths: "\\server\share\dir\file"
	* - absolute paths on current drive: "\dir\file"
	* - relative paths on other drive: "X:file"
	* - prefixed paths: "\\?\...", "\\.\..."
	*/

	/* convert to absolute path using GetFullPathNameW */
	result = GetFullPathNameW(path, MAX_LONG_PATH, buf, NULL);
	if (!result)
	{
		errno = err_win_to_posix(GetLastError());
		return -1;
	}

	/*
	* return absolute path if it fits within max_path (even if
	* "cwd + path" doesn't due to '..' components)
	*/
	if (result < max_path)
	{
		wcscpy(path, buf);
		return result;
	}

	/* error out if we shouldn't expand the path or buf is too small */
	if (!expand || result >= MAX_LONG_PATH - 6)
	{
		errno = ENAMETOOLONG;
		return -1;
	}

	/* prefix full path with "\\?\" or "\\?\UNC\" */
	if (buf[0] == '\\')
	{
		/* ...unless already prefixed */
		if (buf[1] == '\\' && (buf[2] == '?' || buf[2] == '.'))
			return len;

		wcscpy(path, L"\\\\?\\UNC\\");
		wcscpy(path + 8, buf + 2);
		return result + 6;
	}
	else
	{
		wcscpy(path, L"\\\\?\\");
		wcscpy(path + 4, buf);
		return result + 4;
	}
}

int mingw_mkdir(const char *path, int mode)
{
	int ret;
	wchar_t wpath[MAX_LONG_PATH];
	/* CreateDirectoryW path limit is 248 (MAX_PATH - 8.3 file name) */
	if (xutftowcs_path_ex(wpath, path, MAX_LONG_PATH, -1, 248,
		core_long_paths) < 0)
		return -1;

	ret = _wmkdir(wpath);
	if (!ret)
		process_phantom_symlinks();
	if (!ret && needs_hiding(path))
		return set_hidden_flag(wpath, 1);
	return ret;
}

int mingw_open(const char *filename, int oflags, ...)
{
	va_list args;
	unsigned mode;
	int fd;
	wchar_t wfilename[MAX_LONG_PATH];

	va_start(args, oflags);
	mode = va_arg(args, int);
	va_end(args);

	if (filename && !strcmp(filename, "/dev/null"))
		filename = "nul";

	if (xutftowcs_long_path(wfilename, filename) < 0)
		return -1;
	fd = _wopen(wfilename, oflags, mode);

	if (fd < 0 && (oflags & O_ACCMODE) != O_RDONLY && errno == EACCES)
	{
		DWORD attrs = GetFileAttributesW(wfilename);
		if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY))
			errno = EISDIR;
	}
	if ((oflags & O_CREAT) && needs_hiding(filename))
	{
		/*
		* Internally, _wopen() uses the CreateFile() API which errors
		* out with an ERROR_ACCESS_DENIED if CREATE_ALWAYS was
		* specified and an already existing file's attributes do not
		* match *exactly*. As there is no mode or flag we can set that
		* would correspond to FILE_ATTRIBUTE_HIDDEN, let's just try
		* again *without* the O_CREAT flag (that corresponds to the
		* CREATE_ALWAYS flag of CreateFile()).
		*/
		if (fd < 0 && errno == EACCES)
			fd = _wopen(wfilename, oflags & ~O_CREAT, mode);
		if (fd >= 0 && set_hidden_flag(wfilename, 1))
			warning("could not mark '%s' as hidden.", filename);
	}
	return fd;
}

/* cached length of current directory for handle_long_path */
static int current_directory_len = 0;

int mingw_chdir(const char *dirname)
{
	int result;
	DECLARE_PROC_ADDR(kernel32.dll, DWORD, GetFinalPathNameByHandleW,
	HANDLE, LPWSTR, DWORD, DWORD);
	wchar_t wdirname[MAX_LONG_PATH];
	if (xutftowcs_long_path(wdirname, dirname) < 0)
		return -1;

	if (has_symlinks && INIT_PROC_ADDR(GetFinalPathNameByHandleW))
	{
		HANDLE hnd = CreateFileW(wdirname, 0,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
			OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
		if (hnd == INVALID_HANDLE_VALUE)
		{
			errno = err_win_to_posix(GetLastError());
			return -1;
		}
		if (!GetFinalPathNameByHandleW(hnd, wdirname, ARRAY_SIZE(wdirname), 0))
		{
			errno = err_win_to_posix(GetLastError());
			CloseHandle(hnd);
			return -1;
		}
		CloseHandle(hnd);
	}

	result = _wchdir(normalize_ntpath(wdirname));
	current_directory_len = GetCurrentDirectoryW(0, NULL);
	return result;
}

char *mingw_mktemp(char *template)
{
	wchar_t wtemplate[MAX_PATH];
	/* we need to return the path, thus no long paths here! */
	if (xutftowcs_path(wtemplate, template) < 0)
		return NULL;
	if (!_wmktemp(wtemplate))
		return NULL;
	if (xwcstoutf(template, wtemplate, strlen(template) + 1) < 0)
		return NULL;
	return template;
}

int mingw_unlink(const char *pathname)
{
	int tries = 0;
	wchar_t wpathname[MAX_LONG_PATH];
	if (xutftowcs_long_path(wpathname, pathname) < 0)
		return -1;

	do
	{
		/* read-only files cannot be removed */
		_wchmod(wpathname, 0666);
		if (!_wunlink(wpathname))
			return 0;
		if (!is_file_in_use_error(GetLastError()))
			break;
		/*
		* _wunlink() / DeleteFileW() for directory symlinks fails with
		* ERROR_ACCESS_DENIED (EACCES), so try _wrmdir() as well. This is the
		* same error we get if a file is in use (already checked above).
		*/
		if (!_wrmdir(wpathname))
			return 0;
	} while (retry_ask_yes_no(&tries, "Unlink of file '%s' failed. "
		"Should I try again?", pathname));
	return -1;
}

#endif