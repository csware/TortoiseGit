// TortoiseGit - a Windows shell extension for easy version control

// Copyright (C) 2008-2009, 2011-2013, 2015 - TortoiseGit
// Copyright (C) 2003-2011, 2013 - TortoiseSVN

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
#include "TortoiseProc.h"
#include "TGitPath.h"
#include "RenameDlg.h"
#include "AppUtils.h"
#include "ControlsBridge.h"
#include "Git.h"

IMPLEMENT_DYNAMIC(CRenameDlg, CHorizontalResizableStandAloneDialog)
CRenameDlg::CRenameDlg(CWnd* pParent /*=NULL*/)
	: CHorizontalResizableStandAloneDialog(CRenameDlg::IDD, pParent)
	, m_name(_T(""))
	, m_renameRequired(true)
	, m_pInputValidator(NULL)
	, m_bBalloonVisible(false)
{
}

CRenameDlg::~CRenameDlg()
{
}

void CRenameDlg::DoDataExchange(CDataExchange* pDX)
{
	CHorizontalResizableStandAloneDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_NAME, m_name);
}

HRESULT EnableAutoComplete(HWND hWndEdit, LPCTSTR szCurrentWorkingDirectory = NULL, AUTOCOMPLETELISTOPTIONS acloOptions = ACLO_NONE, AUTOCOMPLETEOPTIONS acoOptions = ACO_AUTOSUGGEST, REFCLSID clsid = CLSID_ACListISF)
{
	IAutoComplete *pac;
	HRESULT hr = CoCreateInstance(CLSID_AutoComplete,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_PPV_ARGS(&pac));
	if (FAILED(hr))
	{
		return hr;
	}

	IUnknown *punkSource;
	hr = CoCreateInstance(clsid,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_PPV_ARGS(&punkSource));
	if (FAILED(hr))
	{
		pac->Release();
		return hr;
	}

	if ((acloOptions != ACLO_NONE) || (szCurrentWorkingDirectory != NULL))
	{
		IACList2 *pal2;
		hr = punkSource->QueryInterface(IID_PPV_ARGS(&pal2));
		if (SUCCEEDED(hr))
		{
			if (acloOptions != ACLO_NONE)
			{
				hr = pal2->SetOptions(acloOptions);
			}

			if (szCurrentWorkingDirectory != NULL)
			{
				ICurrentWorkingDirectory *pcwd;
				hr = pal2->QueryInterface(IID_PPV_ARGS(&pcwd));
				if (SUCCEEDED(hr))
				{
					hr = pcwd->SetDirectory(szCurrentWorkingDirectory);
					pcwd->Release();
				}
			}

			pal2->Release();
		}
	}

	hr = pac->Init(hWndEdit, punkSource, NULL, NULL);

	if (acoOptions != ACO_NONE)
	{
		IAutoComplete2 *pac2;
		hr = pac->QueryInterface(IID_PPV_ARGS(&pac2));
		if (SUCCEEDED(hr))
		{
			hr = pac2->SetOptions(acoOptions);
			pac2->Release();
		}
	}

	punkSource->Release();
	pac->Release();
}

BEGIN_MESSAGE_MAP(CRenameDlg, CHorizontalResizableStandAloneDialog)
	ON_EN_SETFOCUS(IDC_NAME, &CRenameDlg::OnEnSetfocusName)
END_MESSAGE_MAP()

BOOL CRenameDlg::OnInitDialog()
{
	CHorizontalResizableStandAloneDialog::OnInitDialog();
	CAppUtils::MarkWindowAsUnpinnable(m_hWnd);

	EnableAutoComplete(GetDlgItem(IDC_NAME)->m_hWnd, g_Git.m_CurrentDir, ACLO_CURRENTDIR);

	if (!m_windowtitle.IsEmpty())
		this->SetWindowText(m_windowtitle);
	if (!m_label.IsEmpty())
		SetDlgItemText(IDC_LABEL, m_label);

	if (!m_name.IsEmpty())
	{
		CString sTmp;
		sTmp.Format(IDS_RENAME_INFO, (LPCWSTR)m_name);
		SetDlgItemText(IDC_RENINFOLABEL, sTmp);
	}

	AddAnchor(IDC_RENINFOLABEL, TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDC_LABEL, TOP_LEFT);
	AddAnchor(IDC_NAME, TOP_LEFT, TOP_RIGHT);
	AddAnchor(IDOK, BOTTOM_RIGHT);
	AddAnchor(IDCANCEL, BOTTOM_RIGHT);

	CControlsBridge::AlignHorizontally(this, IDC_LABEL, IDC_NAME);
	if (hWndExplorer)
		CenterWindow(CWnd::FromHandle(hWndExplorer));
	EnableSaveRestore(_T("RenameDlg"));
	m_originalName = m_name;
	return TRUE;
}

void CRenameDlg::OnOK()
{
	UpdateData();
	m_name.Trim();
	if (m_pInputValidator)
	{
		CString sError = m_pInputValidator->Validate(IDC_NAME, m_name);
		if (!sError.IsEmpty())
		{
			m_bBalloonVisible = true;
			ShowEditBalloon(IDC_NAME, sError, CString(MAKEINTRESOURCE(IDS_ERR_ERROR)), TTI_ERROR);
			return;
		}
	}
	bool nameAllowed = ((m_originalName != m_name) || !m_renameRequired) && !m_name.IsEmpty();
	if (!nameAllowed)
	{
		m_bBalloonVisible = true;
		ShowEditBalloon(IDC_NAME, IDS_WARN_RENAMEREQUIRED, IDS_ERR_ERROR, TTI_ERROR);
		return;
	}

	CTGitPath path(m_name);
	if (!path.IsValidOnWindows())
	{
		m_bBalloonVisible = true;
		ShowEditBalloon(IDC_NAME, IDS_WARN_NOVALIDPATH, IDS_ERR_ERROR, TTI_ERROR);
		return;
	}
	CHorizontalResizableStandAloneDialog::OnOK();
}

void CRenameDlg::OnCancel()
{
	// find out if there's a balloon tip showing and if there is,
	// hide that tooltip but do NOT exit the dialog.
	if (m_bBalloonVisible)
	{
		Edit_HideBalloonTip(GetDlgItem(IDC_NAME)->GetSafeHwnd());
		return;
	}

	CHorizontalResizableStandAloneDialog::OnCancel();
}

void CRenameDlg::OnEnSetfocusName()
{
	m_bBalloonVisible = false;
}
