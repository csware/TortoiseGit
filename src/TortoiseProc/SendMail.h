// TortoiseGit - a Windows shell extension for easy version control

// Copyright (C) 2012-2013, 2015 - TortoiseGit

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

#include "GitProgressList.h"
#include "TGitPath.h"

enum
{
	SEND_MAIL_SMTP_DIRECT = 0,
	SEND_MAIL_MAPI = 1,
	SEND_MAIL_SMTP_CONFIGURED = 2,
};

class CSendMail
{
protected:
	static int SendMail(CString &FromName, CString &FromMail, CString &To, CString &CC, CString &subject, CString &body, CStringArray &attachments, CString *errortext);
	static int SendMail(const CTGitPath &item, CGitProgressList * instance, CString &FromName, CString &FromMail, CString &To, CString &CC, CString &subject, CString &body, CStringArray &attachments);
	CString	m_sSenderName;
	CString	m_sSenderMail;
	CString	m_sTo;
	CString	m_sCC;
	CString	m_sNotes;
	bool	m_bAttachment;

public:
	CSendMail(CString& To, CString& CC, bool m_bAttachment, CString notes);
	~CSendMail(void);
	virtual int Send(CTGitPathList &list, CGitProgressList * instance) = 0;
};

class CSendMailCombineable : public CSendMail
{
public:
	CSendMailCombineable(CString& To, CString& CC, CString& subject, bool bAttachment, bool bCombine, CString notes);
	~CSendMailCombineable(void);

	virtual int Send(CTGitPathList &list, CGitProgressList * instance);

protected:
	virtual int SendAsSingleMail(const CTGitPath& path, CGitProgressList* instance, bool includeNotes);
	virtual int SendAsCombinedMail(CTGitPathList &list, CGitProgressList * instance);

	CString	m_sSubject;
	bool	m_bCombine;
};
