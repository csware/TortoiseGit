﻿// TortoiseGit - a Windows shell extension for easy version control

// Copyright (C) 2008-2017, 2019-2021, 2023-2025 - TortoiseGit

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
// SettingGitConfig.cpp : implementation file
//

#include "stdafx.h"
#include "TortoiseProc.h"
#include "SettingGitConfig.h"
#include "GitAdminDir.h"
#include "AppUtils.h"

// CSettingGitConfig dialog

IMPLEMENT_DYNAMIC(CSettingGitConfig, ISettingsPropPage)

CSettingGitConfig::CSettingGitConfig()
	: ISettingsPropPage(CSettingGitConfig::IDD)
	, m_bNeedSave(false)
	, m_bQuotePath(TRUE)
	, m_bPrune(FALSE)
	, m_bInheritUserName(FALSE)
	, m_bInheritEmail(FALSE)
	, m_bInheritSigningKey(FALSE)
{
}

CSettingGitConfig::~CSettingGitConfig()
{
}

void CSettingGitConfig::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_GIT_USERNAME, m_UserName);
	DDX_Text(pDX, IDC_GIT_USEREMAIL, m_UserEmail);
	DDX_Text(pDX, IDC_GIT_USERESINGNINGKEY, m_UserSigningKey);
	DDX_Check(pDX, IDC_CHECK_QUOTEPATH, m_bQuotePath);
	DDX_Check(pDX, IDC_CHECK_PRUNE, m_bPrune);
	DDX_Check(pDX, IDC_CHECK_INHERIT_NAME, m_bInheritUserName);
	DDX_Check(pDX, IDC_CHECK_INHERIT_EMAIL, m_bInheritEmail);
	DDX_Check(pDX, IDC_CHECK_INHERIT_KEYID, m_bInheritSigningKey);
	DDX_Control(pDX, IDC_COMBO_AUTOCRLF, m_cAutoCrLf);
	DDX_Control(pDX, IDC_COMBO_SAFECRLF, m_cSafeCrLf);
	GITSETTINGS_DDX
}

BEGIN_MESSAGE_MAP(CSettingGitConfig, CPropertyPage)
	ON_EN_CHANGE(IDC_GIT_USERNAME, &CSettingGitConfig::OnChange)
	ON_EN_CHANGE(IDC_GIT_USEREMAIL, &CSettingGitConfig::OnChange)
	ON_EN_CHANGE(IDC_GIT_USERESINGNINGKEY, &CSettingGitConfig::OnChange)
	ON_CBN_SELCHANGE(IDC_COMBO_AUTOCRLF, &CSettingGitConfig::OnChange)
	ON_BN_CLICKED(IDC_CHECK_QUOTEPATH, &CSettingGitConfig::OnChange)
	ON_BN_CLICKED(IDC_CHECK_PRUNE, &CSettingGitConfig::OnChange)
	ON_CBN_SELCHANGE(IDC_COMBO_SAFECRLF, &CSettingGitConfig::OnChange)
	ON_BN_CLICKED(IDC_CHECK_INHERIT_NAME, &CSettingGitConfig::OnChange)
	ON_BN_CLICKED(IDC_CHECK_INHERIT_EMAIL, &CSettingGitConfig::OnChange)
	ON_BN_CLICKED(IDC_CHECK_INHERIT_KEYID, &CSettingGitConfig::OnChange)
	ON_BN_CLICKED(IDC_EDITGLOBALGITCONFIG, &CSettingGitConfig::OnBnClickedEditglobalgitconfig)
	ON_BN_CLICKED(IDC_EDITGLOBALXDGGITCONFIG, &CSettingGitConfig::OnBnClickedEditglobalxdggitconfig)
	ON_BN_CLICKED(IDC_EDITLOCALGITCONFIG, &CSettingGitConfig::OnBnClickedEditlocalgitconfig)
	ON_BN_CLICKED(IDC_EDITTGITCONFIG, &CSettingGitConfig::OnBnClickedEdittgitconfig)
	ON_BN_CLICKED(IDC_VIEWEFFECTIVEGITCONFIG, &CSettingGitConfig::OnBnClickedVieweffectivegitconfig)
	ON_BN_CLICKED(IDC_EDITSYSTEMGITCONFIG, &CSettingGitConfig::OnBnClickedEditsystemgitconfig)
	ON_BN_CLICKED(IDC_VIEWSYSTEMGITCONFIG, &CSettingGitConfig::OnBnClickedViewsystemgitconfig)
	GITSETTINGS_RADIO_EVENT
END_MESSAGE_MAP()

BOOL CSettingGitConfig::OnInitDialog()
{
	ISettingsPropPage::OnInitDialog();

	m_cAutoCrLf.AddString(L"");
	m_cAutoCrLf.AddString(L"false");
	m_cAutoCrLf.AddString(L"true");
	m_cAutoCrLf.AddString(L"input");

	m_cSafeCrLf.AddString(L"");
	m_cSafeCrLf.AddString(L"false");
	m_cSafeCrLf.AddString(L"true");
	m_cSafeCrLf.AddString(L"warn");

	AdjustControlSize(IDC_CHECK_QUOTEPATH);
	AdjustControlSize(IDC_CHECK_INHERIT_NAME);
	AdjustControlSize(IDC_CHECK_INHERIT_EMAIL);
	AdjustControlSize(IDC_CHECK_INHERIT_KEYID);
	GITSETTINGS_ADJUSTCONTROLSIZE

	m_tooltips.AddTool(IDC_CHECK_INHERIT_NAME, IDS_SETTINGS_GITCONFIG_INHERIT_TT);
	m_tooltips.AddTool(IDC_CHECK_INHERIT_EMAIL, IDS_SETTINGS_GITCONFIG_INHERIT_TT);
	m_tooltips.AddTool(IDC_CHECK_INHERIT_KEYID, IDS_SETTINGS_GITCONFIG_INHERIT_TT);

	InitGitSettings(this, false, &m_tooltips);

	if (!m_bGlobal || m_bIsBareRepo)
		this->GetDlgItem(IDC_EDITLOCALGITCONFIG)->EnableWindow(TRUE);
	else
		this->GetDlgItem(IDC_EDITLOCALGITCONFIG)->EnableWindow(FALSE);

	if (m_bGlobal)
		this->GetDlgItem(IDC_EDITTGITCONFIG)->EnableWindow(FALSE);

	if (m_bIsBareRepo)
	{
		this->GetDlgItem(IDC_EDITLOCALGITCONFIG)->SetWindowText(CString(MAKEINTRESOURCE(IDS_PROC_GITCONFIG_EDITLOCALGONCFIG)));
		this->GetDlgItem(IDC_EDITTGITCONFIG)->SetWindowText(CString(MAKEINTRESOURCE(IDS_PROC_GITCONFIG_VIEWTGITCONFIG)));
	}

	if (!CAppUtils::IsAdminLogin())
	{
		static_cast<CButton*>(this->GetDlgItem(IDC_EDITSYSTEMGITCONFIG))->SetShield(TRUE);
		GetDlgItem(IDC_VIEWSYSTEMGITCONFIG)->EnableWindow(TRUE);
		this->GetDlgItem(IDC_VIEWSYSTEMGITCONFIG)->ShowWindow(SW_SHOW);
	}

	if (PathIsDirectory(g_Git.GetGitGlobalXDGConfig(true)))
	{
		GetDlgItem(IDC_EDITGLOBALXDGGITCONFIG)->EnableWindow(TRUE);
		this->GetDlgItem(IDC_EDITGLOBALXDGGITCONFIG)->ShowWindow(SW_SHOW);
	}

	this->UpdateData(FALSE);

	if (m_UserName.IsEmpty() && m_UserEmail.IsEmpty())
	{
		// preselect "global" and remove check in "inherit" checkboxes if no username and email are set on first open
		m_iConfigSource = CFG_SRC_GLOBAL;
		CheckRadioButton(IDC_RADIO_SETTINGS_EFFECTIVE, IDC_RADIO_SETTINGS_SYSTEM, IDC_RADIO_SETTINGS_EFFECTIVE + m_iConfigSource);
		m_cSaveTo.SelectString(0, CString(MAKEINTRESOURCE(IDS_CONFIG_GLOBAL)));
		LoadData();
		m_bInheritUserName = FALSE;
		m_bInheritEmail = FALSE;
		EnDisableControls();
	}
	return TRUE;
}
// CSettingGitConfig message handlers

void CSettingGitConfig::LoadDataImpl(CAutoConfig& config)
{
	m_bInheritSigningKey = (config.GetString(L"user.signingkey", m_UserSigningKey) == GIT_ENOTFOUND);

	// special handling for UserName and UserEmail, because these can also be defined as environment variables for effective settings
	if (m_iConfigSource == CFG_SRC_EFFECTIVE)
	{
		m_UserName = g_Git.GetUserName();
		m_UserEmail = g_Git.GetUserEmail();
		m_bInheritUserName = FALSE;
		m_bInheritEmail = FALSE;
		m_bInheritSigningKey = FALSE;
	}
	else
	{
		m_bInheritUserName = (config.GetString(L"user.name", m_UserName) == GIT_ENOTFOUND);
		m_bInheritEmail = (config.GetString(L"user.email", m_UserEmail) == GIT_ENOTFOUND);
	}

	BOOL bAutoCrLf = FALSE;
	if (git_config_get_bool(&bAutoCrLf, config, "core.autocrlf") == GIT_ENOTFOUND)
		m_cAutoCrLf.SetCurSel(0);
	else if (bAutoCrLf)
		m_cAutoCrLf.SetCurSel(2);
	else
	{
		CString sAutoCrLf;
		config.GetString(L"core.autocrlf", sAutoCrLf);
		sAutoCrLf = sAutoCrLf.MakeLower().Trim();
		if (sAutoCrLf == L"input")
			m_cAutoCrLf.SetCurSel(3);
		else
			m_cAutoCrLf.SetCurSel(1);
	}

	if (git_config_get_bool(&m_bQuotePath, config, "core.quotepath") == GIT_ENOTFOUND)
	{
		if (m_iConfigSource == CFG_SRC_EFFECTIVE)
			m_bQuotePath = BST_CHECKED;
		else
			m_bQuotePath = BST_INDETERMINATE;
	}

	if (git_config_get_bool(&m_bPrune, config, "fetch.prune") == GIT_ENOTFOUND)
	{
		if (m_iConfigSource == CFG_SRC_EFFECTIVE)
			m_bPrune = BST_UNCHECKED;
		else
			m_bPrune = BST_INDETERMINATE;
	}

	BOOL bSafeCrLf = FALSE;
	if (git_config_get_bool(&bSafeCrLf, config, "core.safecrlf") == GIT_ENOTFOUND)
		m_cSafeCrLf.SetCurSel(0);
	else if (bSafeCrLf)
		m_cSafeCrLf.SetCurSel(2);
	else
	{
		CString sSafeCrLf;
		config.GetString(L"core.safecrlf", sSafeCrLf);
		sSafeCrLf = sSafeCrLf.MakeLower().Trim();
		if (sSafeCrLf == L"warn")
			m_cSafeCrLf.SetCurSel(3);
		else
			m_cSafeCrLf.SetCurSel(1);
	}

	m_bNeedSave = false;
	SetModified(FALSE);
	UpdateData(FALSE);
}

void CSettingGitConfig::EnDisableControls()
{
	GetDlgItem(IDC_GIT_USERNAME)->SendMessage(EM_SETREADONLY, m_iConfigSource == CFG_SRC_EFFECTIVE, 0);
	GetDlgItem(IDC_GIT_USEREMAIL)->SendMessage(EM_SETREADONLY, m_iConfigSource == CFG_SRC_EFFECTIVE, 0);
	GetDlgItem(IDC_GIT_USERESINGNINGKEY)->SendMessage(EM_SETREADONLY, m_iConfigSource == CFG_SRC_EFFECTIVE, 0);
	GetDlgItem(IDC_COMBO_AUTOCRLF)->EnableWindow(m_iConfigSource != CFG_SRC_EFFECTIVE);
	GetDlgItem(IDC_CHECK_QUOTEPATH)->EnableWindow(m_iConfigSource != CFG_SRC_EFFECTIVE);
	GetDlgItem(IDC_CHECK_PRUNE)->EnableWindow(m_iConfigSource != CFG_SRC_EFFECTIVE);
	GetDlgItem(IDC_COMBO_SAFECRLF)->EnableWindow(m_iConfigSource != CFG_SRC_EFFECTIVE);
	GetDlgItem(IDC_COMBO_SETTINGS_SAFETO)->EnableWindow(m_iConfigSource != CFG_SRC_EFFECTIVE);
	GetDlgItem(IDC_CHECK_INHERIT_NAME)->EnableWindow(m_iConfigSource != CFG_SRC_EFFECTIVE);
	GetDlgItem(IDC_CHECK_INHERIT_EMAIL)->EnableWindow(m_iConfigSource != CFG_SRC_EFFECTIVE);
	GetDlgItem(IDC_CHECK_INHERIT_KEYID)->EnableWindow(m_iConfigSource != CFG_SRC_EFFECTIVE);

	GetDlgItem(IDC_GIT_USERNAME)->EnableWindow(!m_bInheritUserName);
	GetDlgItem(IDC_GIT_USEREMAIL)->EnableWindow(!m_bInheritEmail);
	GetDlgItem(IDC_GIT_USERESINGNINGKEY)->EnableWindow(!m_bInheritSigningKey);
	UpdateData(FALSE);
}

void CSettingGitConfig::OnChange()
{
	UpdateData();
	EnDisableControls();
	m_bNeedSave = true;
	SetModified();
}

BOOL CSettingGitConfig::SafeDataImpl(CAutoConfig& config)
{
	if (!Save(config, L"user.name", m_UserName, m_bInheritUserName == TRUE))
		return FALSE;

	if (!Save(config, L"user.email", m_UserEmail, m_bInheritEmail == TRUE))
		return FALSE;

	if (!Save(config, L"user.signingkey", this->m_UserSigningKey, m_bInheritSigningKey == TRUE))
		return FALSE;

	if (!Save(config, L"core.quotepath", m_bQuotePath ? L"true" : L"false", m_bQuotePath == BST_INDETERMINATE))
		return FALSE;

	if (!Save(config, L"fetch.prune", m_bPrune ? L"true" : L"false", m_bPrune == BST_INDETERMINATE))
		return FALSE;

	{
		CString autocrlf;
		m_cAutoCrLf.GetWindowText(autocrlf);
		if (!Save(config, L"core.autocrlf", autocrlf, autocrlf.IsEmpty()))
			return FALSE;
	}

	{
		CString safecrlf;
		this->m_cSafeCrLf.GetWindowText(safecrlf);
		if (!Save(config, L"core.safecrlf", safecrlf, safecrlf.IsEmpty()))
			return FALSE;
	}

	return TRUE;
}

BOOL CSettingGitConfig::OnApply()
{
	if (!m_bNeedSave)
		return TRUE;
	UpdateData();
	if (!SafeData())
		return FALSE;
	m_bNeedSave = false;
	SetModified(FALSE);
	return ISettingsPropPage::OnApply();
}

void CSettingGitConfig::OnBnClickedEditglobalgitconfig()
{
	// use alternative editor because of LineEndings
	CAppUtils::LaunchAlternativeEditor(g_Git.GetGitGlobalConfig());
}

void CSettingGitConfig::OnBnClickedEditglobalxdggitconfig()
{
	// use alternative editor because of LineEndings
	CAppUtils::LaunchAlternativeEditor(g_Git.GetGitGlobalXDGConfig());
}

void CSettingGitConfig::OnBnClickedEditlocalgitconfig()
{
	// use alternative editor because of LineEndings
	CAppUtils::LaunchAlternativeEditor(g_Git.GetGitLocalConfig());
}

void CSettingGitConfig::OnBnClickedEdittgitconfig()
{
	// use alternative editor because of LineEndings
	if (GitAdminDir::IsBareRepo(g_Git.m_CurrentDir))
	{
		CString tmpFile = GetTempFile();
		if (tmpFile.IsEmpty())
		{
			MessageBox(L"Could not create temp file.", L"TortoiseGit", MB_OK | MB_ICONERROR);
			return;
		}
		CTGitPath path(L".tgitconfig");
		if (g_Git.GetOneFile(L"HEAD", path, tmpFile) == 0)
		{
			::SetFileAttributes(tmpFile, FILE_ATTRIBUTE_READONLY);
			CAppUtils::LaunchAlternativeEditor(tmpFile);
		}
	}
	else
	{
		CAppUtils::LaunchAlternativeEditor(g_Git.m_CurrentDir + L"\\.tgitconfig");
	}
}

void CSettingGitConfig::OnBnClickedVieweffectivegitconfig()
{
	CString err;
	CString tempfile = ::GetTempFile();
	if (tempfile.IsEmpty())
	{
		MessageBox(L"Could not create temp file.", L"TortoiseGit", MB_OK | MB_ICONERROR);
		return;
	}

	CString cmd = L"git config --show-origin -l";
	if (g_Git.RunLogFile(cmd, tempfile, &err))
	{
		CMessageBox::Show(GetSafeHwnd(), L"Could not get effective git config:\n" + err, L"TortoiseGit", MB_OK);
		return;
	}
	::SetFileAttributes(tempfile, FILE_ATTRIBUTE_READONLY);
	CAppUtils::LaunchAlternativeEditor(tempfile);
}

void CSettingGitConfig::OnBnClickedEditsystemgitconfig()
{
	CString filename = g_Git.GetGitSystemConfig();
	if (filename.IsEmpty())
	{
		CMessageBox::Show(GetSafeHwnd(), IDS_PROC_GITCONFIG_NOMSYSGIT, IDS_APPNAME, MB_ICONERROR);
		return;
	}
	// use alternative editor because of LineEndings
	CAppUtils::LaunchAlternativeEditor(filename, true);
}

void CSettingGitConfig::OnBnClickedViewsystemgitconfig()
{
	CString filename = g_Git.GetGitSystemConfig();
	if (filename.IsEmpty())
	{
		CMessageBox::Show(GetSafeHwnd(), IDS_PROC_GITCONFIG_NOMSYSGIT, IDS_APPNAME, MB_ICONERROR);
		return;
	}
	// use alternative editor because of LineEndings
	CAppUtils::LaunchAlternativeEditor(filename);
}
