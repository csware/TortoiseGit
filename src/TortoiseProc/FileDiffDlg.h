﻿// TortoiseGit - a Windows shell extension for easy version control

// Copyright (C) 2008-2017, 2019-2020, 2023-2025 - TortoiseGit
// Copyright (C) 2003-2008 - TortoiseSVN

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
#include "afxcmn.h"
#include "StandAloneDlg.h"
#include "GitRev.h"
#include "TGitPath.h"
#include "HintCtrl.h"
#include "Colors.h"
#include "FilterEdit.h"
#include "MenuButton.h"
#include "ACEdit.h"
#include "GestureEnabledControl.h"
#include "LogDlgFileFilter.h"
#include "PatchViewDlg.h"
#include "HyperLink.h"
#include "ThemeControls.h"

#define IDT_FILTER		101
#define IDT_INPUT		102
#define IDT_FILLPATCHVTIMER 103

/**
 * \ingroup TortoiseProc
 * Dialog which fetches and shows the difference between two urls in the
 * repository. It shows a list of files/folders which were changed in those
 * two revisions.
 */
#define MSG_REF_LOADED	(WM_USER+120)

class CFileDiffDlg : public CResizableStandAloneDialog, IHasPatchView
{
	DECLARE_DYNAMIC(CFileDiffDlg)
public:
	CFileDiffDlg(CWnd* pParent = nullptr);
	virtual ~CFileDiffDlg();

	void SetDiff(const CTGitPath* path, const GitRev& baseRev1, const GitRev& rev2);
	void SetDiff(const CTGitPath* path, const GitRev& baseRev1);
	void SetDiff(const CTGitPath* path, const CString& baseHash1, const CString& hash2);

	void	DoBlame(bool blame = true) {m_bBlame = blame;}

	enum { IDD = IDD_DIFFFILES };

protected:
	void DoDataExchange(CDataExchange* pDX) override;    // DDX/DDV support
	void OnCancel() override;
	void OnOK() override;
	BOOL OnInitDialog() override;
	BOOL PreTranslateMessage(MSG* pMsg) override;
	afx_msg LRESULT OnRefLoad(WPARAM wParam, LPARAM lParam);
	afx_msg void OnNMDblclkFilelist(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLvnGetInfoTipFilelist(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnNMCustomdrawFilelist(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnContextMenu(CWnd* /*pWnd*/, CPoint /*point*/);
	afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message);
	afx_msg void OnEnSetfocusSecondurl();
	afx_msg void OnEnSetfocusFirsturl();
	afx_msg void OnBnClickedSwitchleftright();
	afx_msg void OnHdnItemclickFilelist(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedRev1btn();
	afx_msg void OnBnClickedRev2btn();
	afx_msg LRESULT OnClickedCancelFilter(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnEnUpdate(WPARAM wParam, LPARAM lParam);
	afx_msg void OnEnChangeFilter();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnBnClickedDiffoption();
	afx_msg void OnBnClickedLog();
	afx_msg LRESULT OnDisableButtons(WPARAM, LPARAM);
	afx_msg LRESULT OnDiffFinished(WPARAM, LPARAM);
	afx_msg void OnLvnBegindrag(NMHDR* pNMHDR, LRESULT* pResult);

	DECLARE_MESSAGE_MAP()

	int					AddEntry(const CTGitPath * fd);
	void				DoDiff(int selIndex, bool blame);
	void				SetURLLabels(int mask=0x3);
	void				ClearURLabels(int mask);
	void				Filter(const CString& sFilterText);
	void				CopySelectionToClipboard(BOOL isFull=FALSE);

	void				ClickRevButton(CMenuButton *button,GitRev *rev, CACEdit *edit);

	void				EnableInputControl(bool b=true);

	int					RevertSelectedItemToVersion(const CGitHash& rev, bool isOldVersion);

	bool				CheckMultipleDiffs();

	int					FillRevFromString(GitRev* rev, const CString& str)
	{
		GitRev gitrev;
		if (gitrev.GetCommit(str))
		{
			MessageBox(gitrev.GetLastErr(), L"TortoiseGit", MB_ICONERROR);
			return -1;
		}
		gitrev.ApplyMailmap();
		*rev=gitrev;
		return 0;
	}

private:
	static UINT			WM_DISABLEBUTTONS;
	static UINT			WM_DIFFFINISHED;

	static UINT			DiffThreadEntry(LPVOID pVoid);
	UINT				DiffThread();

	static UINT			LoadRefThreadEntry(LPVOID pVoid)
	{
		return static_cast<CFileDiffDlg*>(pVoid)->LoadRefThread();
	};

	UINT				LoadRefThread();

	STRING_VECTOR		m_Reflist;

	BOOL DestroyWindow() override;
	void OnTextUpdate(CACEdit *pEdit);

	CMenuButton			m_cRev1Btn;
	CMenuButton			m_cRev2Btn;
	CFilterEdit			m_cFilter;
	std::atomic<std::shared_ptr<CLogDlgFileFilter>> m_filter;

	CMenuButton			m_cDiffOptionsBtn;

	CThemeMFCButton		m_SwitchButton;
	CColors				m_colors;
	CFont				m_font;
	CGestureEnabledControlTmpl<CHintCtrl<CListCtrl>>	m_cFileList;
	bool				m_bBlame = false;
	CTGitPathList		m_arFileList;
	std::vector<const CTGitPath*> m_arFilteredList;

	CString				m_strExportDir;

	int					m_nIconFolder = 0;

	bool				m_bIsBare = false;
	CTGitPath			m_path;
	GitRev				m_rev1;
	GitRev				m_rev2;

	volatile LONG		m_bThreadRunning = FALSE;

	volatile LONG		m_bLoadingRef = FALSE;

	void				Sort();
	static bool			SortCompare(const CTGitPath& Data1, const CTGitPath& Data2);

	static BOOL			m_bAscending;
	static int			m_nSortedColumn;

	CACEdit				m_ctrRev1Edit;
	CACEdit				m_ctrRev2Edit;

	bool				m_bIgnoreSpaceAtEol = false;
	bool				m_bIgnoreSpaceChange = false;
	bool				m_bIgnoreAllSpace = false;
	bool				m_bIgnoreBlankLines = false;
	bool				m_bCommonAncestorDiff = false;

	CHyperLink m_ctrlShowPatch;
	afx_msg void OnStnClickedViewPatch();
	CPatchViewDlg m_patchViewdlg;
	void FillPatchView(bool onlySetTimer = false);
	CWnd* GetPatchViewParentWnd() override { return this; }
	void TogglePatchView() override;
	afx_msg void OnFileListItemChanged(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnMoving(UINT fwSide, LPRECT pRect);
	afx_msg void OnSizing(UINT fwSide, LPRECT pRect);

public:
	CString				m_strRev1;
	CString				m_strRev2;
	CString				m_sFilter;
};
