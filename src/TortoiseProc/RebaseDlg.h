﻿// TortoiseGit - a Windows shell extension for easy version control

// Copyright (C) 2008-2023, 2025 - TortoiseGit

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
#include "StandAloneDlg.h"
#include "GitStatusListCtrl.h"
#include "SciEdit.h"
#include "SplitterControl.h"
#include "HistoryCombo.h"
#include "GitLogList.h"
#include "MenuButton.h"
#include "ProjectProperties.h"

// CRebaseDlg dialog
#define IDC_REBASE_TAB 0x1000000

#define REBASE_TAB_CONFLICT	0
#define REBASE_TAB_MESSAGE	1
#define REBASE_TAB_LOG		2

#define MSG_REBASE_UPDATE_UI	(WM_USER+151)

class CRebaseDlg : public CResizableStandAloneDialog
{
	DECLARE_DYNAMIC(CRebaseDlg)

public:
	CRebaseDlg(CWnd* pParent = nullptr); // standard constructor
	virtual ~CRebaseDlg();

// Dialog Data
	enum { IDD = IDD_REBASE };

	enum class RebaseStage
	{
		Choose_Branch,
		Choose_Commit_Pick_Mode,
		Start,
		Continue,
		Abort,
		Finish,
		Conclict,
		Edit,
		Squash_Edit,
		Squash_Conclict,
		Done,
		Error,
	};

protected:
	void DoDataExchange(CDataExchange* pDX) override; // DDX/DDV support
	BOOL OnInitDialog() override;
	DECLARE_MESSAGE_MAP()
	LRESULT DefWindowProc(UINT message, WPARAM wParam, LPARAM lParam) override;
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg LRESULT OnRebaseUpdateUI(WPARAM wParam, LPARAM lParam);
	void SetTheme(bool bDark) override;
	void DoSize(int delta);
	void AddRebaseAnchor();

	void SetSplitterRange();
	void SaveSplitterPos();

	void LoadBranchInfo();
	void FetchLogList();
	void SetAllRebaseAction(int action);
	void OnCancel() override;

	CRect m_DlgOrigRect;
	CRect m_CommitListOrigRect;
	CString m_sStatusText;
	bool m_bStatusWarning = false;
	BOOL PreTranslateMessage(MSG* pMsg) override;
	bool LogListHasFocus(HWND hwnd);
	bool LogListHasMenuItem(int i);

	CSciEdit m_wndOutputRebase;
	void SetContinueButtonText();
	void SetControlEnable();
	void UpdateProgress();
	void UpdateCurrentStatus();
	void ListConflictFile(bool noStoreScrollPosition);
	int	RunGitCmdRetryOrAbort(const CString& cmd);
	int  DoRebase();
	afx_msg LRESULT OnGitStatusListCtrlNeedsRefresh(WPARAM, LPARAM);
	void Refresh();
	volatile LONG m_bThreadRunning = FALSE;
	volatile LONG m_bAbort = FALSE;
	int  RebaseThread();
	static UINT RebaseThreadEntry(LPVOID pVoid) { return static_cast<CRebaseDlg*>(pVoid)->RebaseThread(); };
	BOOL IsEnd();

	int IsCommitEmpty(const CGitHash& hash);

	bool m_IsFastForward = false;

	CGitHash m_OrigBranchHash;
	CGitHash m_OrigUpstreamHash;
	CString m_OrigHEADBranch;
	CGitHash m_OrigHEADHash;

	ProjectProperties m_ProjectProperties;

	int VerifyNoConflict();

	CString m_SquashMessage;
	bool m_CurrentCommitEmpty = false;
	struct SquashFirstMetaData
	{
		CString name;
		CString email;
		CTime time;
		bool set = false;

		SquashFirstMetaData() = default;

		SquashFirstMetaData(GitRev* rev)
			: set(true)
			, name(rev->GetAuthorName())
			, email(rev->GetAuthorEmail())
			, time(rev->GetAuthorDate())
		{
		}

		void UpdateDate(GitRev* rev)
		{
			ATLASSERT(set);
			time = rev->GetAuthorDate();
		}

		void Empty()
		{
			set = false;
			name.Empty();
			email.Empty();
			time = 0;
		}

		CString GetAuthor() const
		{
			if (!set)
				return CString();
			CString temp;
			temp.Format(L"%s <%s>", static_cast<LPCWSTR>(name), static_cast<LPCWSTR>(email));
			return temp;
		}

		CString GetAsParam(bool now) const
		{
			if (!set)
				return CString();

			CString date = time.Format(L"%Y-%m-%dT%H:%M:%S");
			if (now)
				date = L"\"now\"";

			CString temp;
			temp.Format(L"--date=%s --author=\"%s\" ", static_cast<LPCWSTR>(date), static_cast<LPCWSTR>(GetAuthor()));
			return temp;
		}
	} m_SquashFirstMetaData;
	int m_iSquashdate = 0;

	int CheckNextCommitIsSquash();
	int GetCurrentCommitID();
	int FinishRebase();
	void RewriteNotes();

	CMenuButton m_PostButton;

	afx_msg void OnBnClickedRebaseSplit();
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnCbnSelchangeBranch();
	afx_msg void OnCbnSelchangeUpstream();
	afx_msg void OnBnClickedContinue();
	afx_msg void OnBnClickedAbort();
	afx_msg void OnLvnItemchangedLoglist(NMHDR *pNMHDR, LRESULT *pResult);
	void FillLogMessageCtrl();

	CProgressCtrl		m_ProgressBar;
	CStatic				m_CtrlStatusText;

	BOOL				m_bAddCherryPickedFrom;
	BOOL				m_bAutoSkipFailedCommit = FALSE;
	bool				m_bRebaseAutoEnd = false;

public:
	CStringArray		m_PostButtonTexts;
	CGitLogList			m_CommitList;

	CString				m_Upstream;
	CString				m_Branch;
	CString				m_Onto;

	bool				m_IsCherryPick = false;
	bool				m_bRebaseAutoStart = false;
	BOOL				m_bPreserveMerges;
	BOOL				m_bForce;
protected:
	CSplitterControl	m_wndSplitter;
	CMFCTabCtrl			m_ctrlTabCtrl;
	CGitStatusListCtrl	m_FileListCtrl;
	CSciEdit			m_LogMessageCtrl;

	CHistoryCombo		m_BranchCtrl;
	CHistoryCombo		m_UpstreamCtrl;

	CMenuButton			m_SplitAllOptions;

	BOOL				m_bSplitCommit;

	RebaseStage			m_RebaseStage = RebaseStage::Choose_Branch;
	bool				m_bFinishedRebase = false;
	bool				m_bStashed = false;

	std::unordered_map<CGitHash, CGitHash> m_rewrittenCommitsMap;
	std::vector<CGitHash> m_forRewrite;
	std::unordered_map<CGitHash, GIT_REV_LIST> m_droppedCommitsMap;
	std::vector<CGitHash> m_currentCommits;

	void AddBranchToolTips(CHistoryCombo& pBranch);
	void AddLogString(const CString& str);
	int WriteReflog(CGitHash hash, const char* message);
	int StartRebase();
	int CheckRebaseCondition();
	void CheckRestoreStash();
	int m_CurrentRebaseIndex = -1;
	int GoNext();
	void ResetParentForSquash(const CString& commitMessage);
	void CleanUpRebaseActiveFolder();
	afx_msg void OnBnClickedButtonReverse();
	afx_msg void OnBnClickedButtonBrowse();
	afx_msg void OnBnClickedRebaseCheckForce();
	afx_msg void OnBnClickedCheckCherryPickedFrom();
	afx_msg void OnBnClickedRebasePostButton();
	afx_msg void OnBnClickedSplitAllOptions();
	afx_msg void OnBnClickedButtonUp();
	afx_msg void OnBnClickedButtonDown();
	afx_msg void OnHelp();

	afx_msg LRESULT	OnTaskbarBtnCreated(WPARAM wParam, LPARAM lParam);
	CComPtr<ITaskbarList3>	m_pTaskbarList;

	afx_msg LRESULT OnRebaseActionMessage(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnCommitsReordered(WPARAM wParam, LPARAM lParam);
	afx_msg void OnRefreshFilelist();
	afx_msg void OnBnClickedRebaseSplitCommit();
	afx_msg void OnBnClickedButtonOnto();
	afx_msg void OnBnClickedButtonAdd();
};
