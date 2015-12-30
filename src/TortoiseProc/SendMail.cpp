// TortoiseGit - a Windows shell extension for easy version control

// Copyright (C) 2008-2013, 2015 - TortoiseGit

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
#include "SendMail.h"
#include "HwSMTP.h"
#include "MailMsg.h"
#include "Git.h"

class CAppUtils;

CSendMail::CSendMail(CString& To, CString& CC, bool bAttachment, CString notes)
{
	m_sSenderName = g_Git.GetUserName();
	m_sSenderMail = g_Git.GetUserEmail();
	m_sTo = To;
	m_sCC = CC;
	m_bAttachment = bAttachment;
	m_sNotes = notes;
}

CSendMail::~CSendMail(void)
{
}

int CSendMail::SendMail(const CTGitPath &item, CGitProgressList * instance, CString &FromName, CString &FromMail, CString &To, CString &CC, CString &subject, CString &body, CStringArray &attachments)
{
	ASSERT(instance);
	int retry = 0;
	while (retry < 3)
	{
		if (instance->IsCancelled() == TRUE)
		{
			instance->ReportUserCanceled();
			return -1;
		}

		instance->AddNotify(new CGitProgressList::NotificationData(item, IDS_SVNACTION_SENDMAIL_START), CColors::Modified);

		CString error;
		if (SendMail(FromName, FromMail, To, CC, subject, body, attachments, &error) == 0)
			return 0;

		instance->ReportError(error);

		if (instance->IsCancelled() == FALSE) // do not retry/sleep if the user already canceled
		{
			++retry;
			if (retry < 3)
			{
				CString temp;
				temp.LoadString(IDS_SVNACTION_SENDMAIL_RETRY);
				instance->ReportNotification(temp);
				Sleep(2000);
			}
		}
	}
	return -1;
}

int CSendMail::SendMail(CString &FromName, CString &FromMail, CString &To, CString &CC, CString &subject, CString &body, CStringArray &attachments, CString *errortext)
{
	if (CRegDWORD(_T("Software\\TortoiseGit\\TortoiseProc\\SendMail\\DeliveryType"), SEND_MAIL_MAPI) == SEND_MAIL_MAPI)
	{
		CMailMsg mapiSender;
		BOOL bMAPIInit = mapiSender.MAPIInitialize();
		if (!bMAPIInit)
		{
			if (errortext)
				*errortext = mapiSender.GetLastErrorMsg();
			return -1;
		}

		mapiSender.SetShowComposeDialog(TRUE);
		mapiSender.SetFrom(FromMail, FromName);
		mapiSender.SetTo(To);
		if (!CC.IsEmpty())
			mapiSender.SetCC(CC);
		mapiSender.SetSubject(subject);
		mapiSender.SetMessage(body);
		for (int i = 0; i < attachments.GetSize(); ++i)
			mapiSender.AddAttachment(attachments[i]);

		BOOL bSend = mapiSender.Send();
		if (bSend == TRUE)
			return 0;
		else
		{
			if (errortext)
				*errortext = mapiSender.GetLastErrorMsg();
			return -1;
		}
	}
	else
	{
		CString sender;
		sender.Format(_T("%s <%s>"), (LPCTSTR)FromName, (LPCTSTR)FromMail);

		CHwSMTP mail;
		if (CRegDWORD(_T("Software\\TortoiseGit\\TortoiseProc\\SendMail\\DeliveryType"), SEND_MAIL_SMTP_CONFIGURED) == SEND_MAIL_SMTP_CONFIGURED)
		{
			CString recipients(To);
			if (!CC.IsEmpty())
				recipients += L";" + CC;
			if (mail.SendEmail((CString)CRegString(_T("Software\\TortoiseGit\\TortoiseProc\\SendMail\\Address"), _T("")), (CString)CRegString(_T("Software\\TortoiseGit\\TortoiseProc\\SendMail\\Username"), _T("")), (CString)CRegString(_T("Software\\TortoiseGit\\TortoiseProc\\SendMail\\Password"), _T("")), (BOOL)CRegDWORD(_T("Software\\TortoiseGit\\TortoiseProc\\SendMail\\AuthenticationRequired"), FALSE), sender, recipients, subject, body, nullptr, &attachments, CC, (DWORD)CRegDWORD(_T("Software\\TortoiseGit\\TortoiseProc\\SendMail\\Port"), 25), sender, To, (DWORD)CRegDWORD(_T("Software\\TortoiseGit\\TortoiseProc\\SendMail\\Encryption"), 0)) == TRUE)
				return 0;
			else
			{
				if (errortext)
					*errortext = mail.GetLastErrorText();
				return -1;
			}
		}
		else if (mail.SendSpeedEmail(sender, To, subject, body, nullptr, &attachments, CC, sender))
			return 0;
		else
		{
			if (errortext)
				*errortext = mail.GetLastErrorText();
			return -1;
		}
	}
}

CSendMailCombineable::CSendMailCombineable(CString& To, CString& CC, CString& subject, bool bAttachment, bool bCombine, CString notes)
	: CSendMail(To, CC, bAttachment, notes)
	, m_sSubject(subject)
	, m_bCombine(bCombine)
{
}

CSendMailCombineable::~CSendMailCombineable()
{
}

int CSendMailCombineable::Send(CTGitPathList &list, CGitProgressList * instance)
{
	if (m_bCombine)
	{
		return SendAsCombinedMail(list, instance);
	}
	else
	{
		instance->SetItemCountTotal(list.GetCount() + 1);
		for (int i = 0; i < list.GetCount(); ++i)
		{
			instance->SetItemProgress(i);
			if (SendAsSingleMail((CTGitPath&)list[i], instance, i == 0))
				return -1;
		}
		instance->SetItemProgress(list.GetCount() + 1);
	}

	return 0;
}

int GetFileContents(const CString& filename, CString& content)
{
	CStdioFile file;
	if (file.Open(filename, CFile::modeRead))
	{
		CString str;
		while (file.ReadString(str))
		{
			content += str;
			str.Empty();
			content += _T("\n");
		}
		return 0;
	}
	else
		return -1;
}

int CSendMailCombineable::SendAsSingleMail(const CTGitPath& path, CGitProgressList* instance, bool includeNotes)
{
	ASSERT(instance);

	CString pathfile(path.GetWinPathString());

	CString body;
	if (includeNotes)
	{
		body = m_sNotes;
		body += _T("\n---\n");
	}
	CStringArray attachments;
	if (m_bAttachment)
		attachments.Add(pathfile);
	else if (GetFileContents(pathfile, body))
	{
		instance->ReportError(_T("Could not open ") + pathfile);
		return -2;
	}

	return SendMail(path, instance, m_sSenderName, m_sSenderMail, m_sTo, m_sCC, m_sSubject, body, attachments);
}

int CSendMailCombineable::SendAsCombinedMail(CTGitPathList &list, CGitProgressList * instance)
{
	ASSERT(instance);

	CStringArray attachments;
	CString body = m_sNotes;
	if (!body.IsEmpty())
		body += _T("\n\n");
	for (int i = 0; i < list.GetCount(); ++i)
	{
		if (m_bAttachment)
		{
			attachments.Add(list[i].GetWinPathString());
		}
		else
		{
			CString filename(list[i].GetWinPathString());
			body += filename + _T(":\n");
			if (GetFileContents(filename, body))
			{
				instance->ReportError(_T("Could not open ") + filename);
				return -2;
			}
			body += _T("\n");
		}
	}
	return SendMail(CTGitPath(), instance, m_sSenderName, m_sSenderMail, m_sTo, m_sCC, m_sSubject, body, attachments);
}
