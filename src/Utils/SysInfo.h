﻿// TortoiseGit - a Windows shell extension for easy version control

// Copyright (C) 2015-2017, 2021, 2024-2025 - TortoiseGit
// Copyright (C) 2008 - TortoiseSVN

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

#pragma once

/**
 * \ingroup Utils
 * This singleton class handles system information
 */
class SysInfo
{
private:
	SysInfo();
	~SysInfo();
	// prevent cloning
	SysInfo(const SysInfo&) = delete;
	SysInfo& operator=(const SysInfo&) = delete;

	bool m_bIsWindows11OrLater;

public:
	static const SysInfo& Instance();

	bool			IsWin11OrLater() const { return m_bIsWindows11OrLater; }
};
