﻿// TortoiseGit - a Windows shell extension for easy version control

// Copyright (C) 2003-2012, 2018, 2021 - TortoiseSVN
// Copyright (C) 2012-2016, 2018-2020, 2023-2025 - TortoiseGit

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
#include "RevisionGraphDlg.h"
#include "Git.h"
#include "AppUtils.h"
#include "RevGraphFilterDlg.h"
#include "DPIAware.h"
#include "LogDlgFilter.h"
#include "GitLogListBase.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

using namespace Gdiplus;

const UINT CRevisionGraphDlg::m_FindDialogMessage = RegisterWindowMessage(FINDMSGSTRING);

struct CToolBarData
{
	WORD wVersion;
	WORD wWidth;
	WORD wHeight;
	WORD wItemCount;
	//WORD aItems[wItemCount]

	WORD* items()
	{
		return reinterpret_cast<WORD*>(this + 1);
	}
};

IMPLEMENT_DYNAMIC(CRevisionGraphDlg, CResizableStandAloneDialog)
CRevisionGraphDlg::CRevisionGraphDlg(CWnd* pParent /*=nullptr*/)
	: CResizableStandAloneDialog(CRevisionGraphDlg::IDD, pParent)
	, m_bFetchLogs(true)
	, m_fZoomFactor(DEFAULT_ZOOM)
	, m_bVisible(true)
{
	// GDI+ initialization

	GdiplusStartupInput input;
	GdiplusStartup(&m_gdiPlusToken, &input, nullptr);

	m_szTip[0] = '\0';
	m_wszTip[0] = L'\0';
}

CRevisionGraphDlg::~CRevisionGraphDlg()
{
	// GDI+ cleanup
	GdiplusShutdown (m_gdiPlusToken);
}

void CRevisionGraphDlg::DoDataExchange(CDataExchange* pDX)
{
	CResizableStandAloneDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CRevisionGraphDlg, CResizableStandAloneDialog)
	ON_WM_SIZE()
	ON_WM_LBUTTONDOWN()

	ON_COMMAND(ID_VIEW_ZOOMIN, OnViewZoomin)
	ON_COMMAND(ID_VIEW_ZOOMOUT, OnViewZoomout)
	ON_COMMAND(ID_VIEW_ZOOM100, OnViewZoom100)
	ON_COMMAND(ID_VIEW_ZOOMHEIGHT, OnViewZoomHeight)
	ON_COMMAND(ID_VIEW_ZOOMWIDTH, OnViewZoomWidth)
	ON_COMMAND(ID_VIEW_ZOOMALL, OnViewZoomAll)
	ON_CBN_SELCHANGE(ID_REVGRAPH_ZOOMCOMBO, OnChangeZoom)
	ON_NOTIFY_EX_RANGE(TTN_NEEDTEXTW, 0, 0xFFFF, OnToolTipNotify)
	ON_NOTIFY_EX_RANGE(TTN_NEEDTEXTA, 0, 0xFFFF, OnToolTipNotify)
	ON_COMMAND(ID_MENUEXIT, OnMenuexit)
	ON_COMMAND(ID_MENUHELP, OnMenuhelp)
	ON_COMMAND(ID_FILE_SAVEGRAPHAS, OnFileSavegraphas)
	ON_COMMAND(ID_VIEW_SHOWOVERVIEW, OnViewShowoverview)
	ON_COMMAND(ID_VIEW_FILTER, OnViewFilter)
	ON_COMMAND(ID_VIEW_COMPAREHEADREVISIONS, OnViewCompareheadrevisions)
	ON_COMMAND(ID_VIEW_COMPAREREVISIONS, OnViewComparerevisions)
	ON_COMMAND(ID_VIEW_UNIFIEDDIFF, OnViewUnifieddiff)
	ON_COMMAND(ID_VIEW_UNIFIEDDIFFOFHEADREVISIONS, OnViewUnifieddiffofheadrevisions)
	ON_WM_WINDOWPOSCHANGING()
	ON_COMMAND(ID_VIEW_SHOWBRANCHINGSANDMERGES, OnViewShowBranchingsMerges)
	ON_COMMAND(ID_VIEW_SHOWALLTAGS, OnViewShowAllTags)
	ON_COMMAND(ID_VIEW_ARROW_POINT_TO_MERGES, OnViewArrowPointToMerges)
	ON_COMMAND(ID_FIND, OnFind)
	ON_REGISTERED_MESSAGE(m_FindDialogMessage, OnFindDialogMessage)
	ON_MESSAGE(WM_DPICHANGED, OnDPIChanged)
END_MESSAGE_MAP()

BOOL CRevisionGraphDlg::InitializeToolbar()
{
	// set up the toolbar
	// add the tool bar to the dialog
	m_ToolBar.CreateEx(this, TBSTYLE_FLAT | TBSTYLE_WRAPABLE | TBSTYLE_TRANSPARENT | CBRS_SIZE_DYNAMIC);

	// LoadToolBar() asserts in debug mode because the bitmap
	// fails to load. That's not a problem because we load the bitmap
	// further down manually.
	// but the assertion is ugly, so we load the button resource here
	// manually as well and call SetButtons().
	HINSTANCE hInst = AfxFindResourceHandle(MAKEINTRESOURCE(IDR_REVGRAPHBAR), RT_TOOLBAR);
	HRSRC hRsrc = ::FindResource(hInst, MAKEINTRESOURCE(IDR_REVGRAPHBAR), RT_TOOLBAR);
	if (!hRsrc)
		return FALSE;

	HGLOBAL hGlobal = LoadResource(hInst, hRsrc);
	if (!hGlobal)
		return FALSE;

	auto pData = reinterpret_cast<CToolBarData*>(LockResource(hGlobal));
	if (!pData)
		return FALSE;
	ASSERT(pData->wVersion == 1);

	auto pItems = std::make_unique<UINT[]>(pData->wItemCount);
	for (int i = 0; i < pData->wItemCount; ++i)
		pItems[i] = pData->items()[i];
	m_ToolBar.SetButtons(pItems.get(), pData->wItemCount);

	UnlockResource(hGlobal);
	FreeResource(hGlobal);

	m_ToolBar.ShowWindow(SW_SHOW);
	m_ToolBar.SetBarStyle(CBRS_ALIGN_TOP | CBRS_TOOLTIPS | CBRS_FLYBY);

	// toolbars aren't true-color without some tweaking:
	{
		CImageList  cImageList;
		CBitmap		cBitmap;
		BITMAP		bmBitmap;

		// load the toolbar with the dimensions of the bitmap itself
		cBitmap.Attach(LoadImage(AfxGetResourceHandle(), MAKEINTRESOURCE(IDR_REVGRAPHBAR),
			IMAGE_BITMAP, 0, 0,
			LR_DEFAULTSIZE | LR_CREATEDIBSECTION));
		cBitmap.GetBitmap(&bmBitmap);
		cBitmap.DeleteObject();
		// now load the toolbar again, but this time with the dpi-scaled dimensions
		// note: we could just load it once and then resize the bitmap, but
		// that's not faster. So loading it again is what we do.
		cBitmap.Attach(LoadImage(AfxGetResourceHandle(), MAKEINTRESOURCE(IDR_REVGRAPHBAR),
			IMAGE_BITMAP,
			CDPIAware::Instance().ScaleX(GetSafeHwnd(), bmBitmap.bmWidth),
			CDPIAware::Instance().ScaleY(GetSafeHwnd(), bmBitmap.bmHeight),
			LR_CREATEDIBSECTION));
		cBitmap.GetBitmap(&bmBitmap);


		CSize	  cSize(bmBitmap.bmWidth, bmBitmap.bmHeight);
		int nNbBtn = cSize.cx / CDPIAware::Instance().ScaleX(GetSafeHwnd(), 20);
		auto rgb = static_cast<RGBTRIPLE*>(bmBitmap.bmBits);
		COLORREF	rgbMask = RGB(rgb[0].rgbtRed, rgb[0].rgbtGreen, rgb[0].rgbtBlue);

		cImageList.Create(CDPIAware::Instance().ScaleX(GetSafeHwnd(), 20), cSize.cy, ILC_COLOR32 | ILC_MASK | ILC_HIGHQUALITYSCALE, nNbBtn, 0);
		cImageList.Add(&cBitmap, rgbMask);
		// set the sizes of the button and images:
		// note: buttonX must be 7 pixels more than imageX, and buttonY must be 6 pixels more than imageY.
		// See the source of SetSizes().
		m_ToolBar.SetSizes(CSize(CDPIAware::Instance().ScaleX(GetSafeHwnd(), 27), CDPIAware::Instance().ScaleY(GetSafeHwnd(), 26)),
			CSize(CDPIAware::Instance().ScaleX(GetSafeHwnd(), 20), CDPIAware::Instance().ScaleY(GetSafeHwnd(), 20)));
		m_ToolBar.SendMessage(TB_SETIMAGELIST, 0, reinterpret_cast<LPARAM>(cImageList.m_hImageList));
		cImageList.Detach();
		cBitmap.Detach();
	}

	RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0);

#define SNAP_WIDTH CDPIAware::Instance().ScaleX(GetSafeHwnd(), 60) // the width of the combo box
	// set up the ComboBox control as a snap mode select box
	// First get the index of the placeholders position in the toolbar
	int zoomComboIndex = 0;
	while (m_ToolBar.GetItemID(zoomComboIndex) != ID_REVGRAPH_ZOOMCOMBO) ++zoomComboIndex;

	// next convert that button to a separator and get its position
	m_ToolBar.SetButtonInfo(zoomComboIndex, ID_REVGRAPH_ZOOMCOMBO, TBBS_SEPARATOR,
			SNAP_WIDTH);
	RECT rect;
	m_ToolBar.GetItemRect(zoomComboIndex, &rect);

	// expand the rectangle to allow the combo box room to drop down
	rect.top += CDPIAware::Instance().ScaleY(GetSafeHwnd(), 3);
	rect.bottom += CDPIAware::Instance().ScaleY(GetSafeHwnd(), 200);

	// then create the combo box and show it
	if (!m_ToolBar.m_ZoomCombo.CreateEx(WS_EX_RIGHT, WS_CHILD|WS_VISIBLE|CBS_AUTOHSCROLL|CBS_DROPDOWN,
		rect, &m_ToolBar, ID_REVGRAPH_ZOOMCOMBO))
	{
		CTraceToOutputDebugString::Instance()(__FUNCTION__ ": Failed to create combo-box\n");
		return FALSE;
	}
	m_ToolBar.m_ZoomCombo.ShowWindow(SW_SHOW);

	// fill the combo box

	const wchar_t* texts[] = { L"5%"
					 , L"10%"
					 , L"20%"
					 , L"40%"
					 , L"50%"
					 , L"75%"
					 , L"100%"
					 , L"200%"
					 , nullptr};

	COMBOBOXEXITEM cbei = { 0 };
	cbei.mask = CBEIF_TEXT;

	for (const wchar_t** text = texts; *text; ++text)
	{
		cbei.pszText = const_cast<wchar_t*>(*text);
		m_ToolBar.m_ZoomCombo.InsertItem(&cbei);
	}

	m_ToolBar.m_ZoomCombo.SetCurSel(1);

	return TRUE;
}

BOOL CRevisionGraphDlg::OnInitDialog()
{
	CResizableStandAloneDialog::OnInitDialog();
	CAppUtils::MarkWindowAsUnpinnable(m_hWnd);
	EnableToolTips();

	CAppUtils::SetWindowTitle(*this, g_Git.m_CurrentDir);


	// set up the status bar
	m_StatusBar.Create(WS_CHILD|WS_VISIBLE|SBT_OWNERDRAW,
		CRect(0,0,0,0), this, 1);
	int strPartDim[2] = { CDPIAware::Instance().ScaleX(GetSafeHwnd(), 120), -1 };
	m_StatusBar.SetParts(2, strPartDim);

	if (InitializeToolbar() != TRUE)
		return FALSE;

	m_pTaskbarList.Release();
	if (FAILED(m_pTaskbarList.CoCreateInstance(CLSID_TaskbarList)))
		m_pTaskbarList = nullptr;

	m_Graph.SetShowOverview(InitialSetMenu(L"ShowRevGraphOverview", false, ID_VIEW_SHOWOVERVIEW));
	m_Graph.m_bShowBranchingsMerges = InitialSetMenu(L"ShowRevGraphBranchesMerges", false, ID_VIEW_SHOWBRANCHINGSANDMERGES);
	m_Graph.m_bShowAllTags = InitialSetMenu(L"ShowRevGraphAllTags", true, ID_VIEW_SHOWALLTAGS);
	m_Graph.m_bArrowPointToMerges = InitialSetMenu(L"ArrowPointToMerges", false, ID_VIEW_ARROW_POINT_TO_MERGES);

//	m_hAccel = LoadAccelerators(AfxGetResourceHandle(),MAKEINTRESOURCE(IDR_ACC_REVISIONGRAPH));


	CRect graphrect = GetGraphRect();
	m_Graph.Init(this, &graphrect);
	m_Graph.SetOwner(this);
	m_Graph.UpdateWindow();
	DoZoom (DEFAULT_ZOOM);

	// begin background operation
	StartWorkerThread();

	EnableSaveRestore(L"RevisionGraphDlg");
//	if (GetExplorerHWND())
//		CenterWindow(CWnd::FromHandle(GetExplorerHWND()));

	SetTheme(CTheme::Instance().IsDarkTheme());

	return TRUE;  // return TRUE unless you set the focus to a control
}

bool CRevisionGraphDlg::InitialSetMenu(const CString& settingName, bool defaultValue, int nId)
{
	CRegDWORD reg = CRegDWORD(L"Software\\TortoiseGit\\" + settingName, defaultValue ? TRUE : FALSE);
	CMenu* pMenu = GetMenu();
	if (!pMenu)
		return static_cast<DWORD>(reg) != FALSE;
	pMenu->CheckMenuItem(nId, MF_BYCOMMAND | (DWORD(reg) ? MF_CHECKED : 0));
	int tbstate = m_ToolBar.GetToolBarCtrl().GetState(nId);
	m_ToolBar.GetToolBarCtrl().SetState(nId, tbstate | (DWORD(reg) ? TBSTATE_CHECKED : 0));
	return static_cast<DWORD>(reg) != FALSE;
}

bool CRevisionGraphDlg::ToggleSetMenu(const CString& settingName, int nId)
{
	CMenu* pMenu = GetMenu();
	if (!pMenu)
		return false;
	int tbstate = m_ToolBar.GetToolBarCtrl().GetState(nId);
	UINT state = pMenu->GetMenuState(nId, MF_BYCOMMAND);
	bool ret = false;
	if (state & MF_CHECKED)
	{
		pMenu->CheckMenuItem(nId, MF_BYCOMMAND | MF_UNCHECKED);
		m_ToolBar.GetToolBarCtrl().SetState(nId, tbstate & (~TBSTATE_CHECKED));
		ret = false;
	}
	else
	{
		pMenu->CheckMenuItem(nId, MF_BYCOMMAND | MF_CHECKED);
		m_ToolBar.GetToolBarCtrl().SetState(nId, tbstate | TBSTATE_CHECKED);
		ret = true;
	}

	CRegDWORD reg = CRegDWORD(L"Software\\TortoiseGit\\" + settingName, FALSE);
	reg = ret;

	return ret;
}

bool CRevisionGraphDlg::UpdateData()
{
	CoInitialize(nullptr);

	if (!m_Graph.FetchRevisionData (m_Graph.m_sPath, nullptr, m_pTaskbarList, m_hWnd))
	{
		// only show the error dialog if we're not in hidden mode
		//if (m_bVisible)
		//{
		//	TGitMessageBox( m_hWnd
		//				   , // m_Graph.m_state.GetLastErrorMessage()
		//				   , L"TortoiseGit"
		//				   , MB_ICONERROR);
		//}
	}

	CoUninitialize();
	m_Graph.PostMessage (CRevisionGraphWnd::WM_WORKERTHREADDONE, 0, 0);

	return true;
}

void CRevisionGraphDlg::SetTheme(bool bDark)
{
	__super::SetTheme(bDark);
	DarkModeHelper::Instance().AllowDarkModeForWindow(m_Graph.GetSafeHwnd(), bDark);
	DarkModeHelper::Instance().AllowDarkModeForWindow(m_StatusBar.GetSafeHwnd(), bDark);
	DarkModeHelper::Instance().AllowDarkModeForWindow(m_ToolBar.GetSafeHwnd(), bDark);

	SetWindowTheme(m_Graph.GetSafeHwnd(), L"Explorer", nullptr);
	SetWindowTheme(m_StatusBar.GetSafeHwnd(), L"Explorer", nullptr);
	SetWindowTheme(m_ToolBar.GetSafeHwnd(), L"Explorer", nullptr);
}

void CRevisionGraphDlg::OnSize(UINT nType, int cx, int cy)
{
	__super::OnSize(nType, cx, cy);
	CRect rect;
	GetClientRect(&rect);
	if (IsWindow(m_ToolBar))
	{
		RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0);
	}
	if (IsWindow(m_StatusBar))
	{
		CRect statusbarrect;
		m_StatusBar.GetClientRect(&statusbarrect);
		statusbarrect.top = rect.bottom - statusbarrect.top + statusbarrect.bottom;
		m_StatusBar.MoveWindow(&statusbarrect);
	}
	if (IsWindow(m_Graph))
	{
		m_Graph.MoveWindow (GetGraphRect());
	}
}

BOOL CRevisionGraphDlg::PreTranslateMessage(MSG* pMsg)
{
#define SCROLL_STEP  20
	if (pMsg->message == WM_KEYDOWN)
	{
		int pos = 0;
		switch (pMsg->wParam)
		{
		case VK_UP:
			pos = m_Graph.GetScrollPos(SB_VERT);
			m_Graph.SetScrollPos(SB_VERT, pos - SCROLL_STEP);
			m_Graph.Invalidate();
			break;
		case VK_DOWN:
			pos = m_Graph.GetScrollPos(SB_VERT);
			m_Graph.SetScrollPos(SB_VERT, pos + SCROLL_STEP);
			m_Graph.Invalidate();
			break;
		case VK_LEFT:
			pos = m_Graph.GetScrollPos(SB_HORZ);
			m_Graph.SetScrollPos(SB_HORZ, pos - SCROLL_STEP);
			m_Graph.Invalidate();
			break;
		case VK_RIGHT:
			pos = m_Graph.GetScrollPos(SB_HORZ);
			m_Graph.SetScrollPos(SB_HORZ, pos + SCROLL_STEP);
			m_Graph.Invalidate();
			break;
		case VK_PRIOR:
			pos = m_Graph.GetScrollPos(SB_VERT);
			m_Graph.SetScrollPos(SB_VERT, pos - GetGraphRect().Height() / 2);
			m_Graph.Invalidate();
			break;
		case VK_NEXT:
			pos = m_Graph.GetScrollPos(SB_VERT);
			m_Graph.SetScrollPos(SB_VERT, pos + GetGraphRect().Height() / 2);
			m_Graph.Invalidate();
			break;
		case VK_F5:
			UpdateFullHistory();
			break;
		case 'F':
			if (GetKeyState(VK_CONTROL) < 0)
				OnFind();
			return TRUE;
		}
	}
	if ((m_hAccel)&&(pMsg->message >= WM_KEYFIRST && pMsg->message <= WM_KEYLAST))
	{
		if (pMsg->wParam == VK_ESCAPE)
			if (m_Graph.CancelMouseZoom())
				return TRUE;
		return TranslateAccelerator(m_hWnd,m_hAccel,pMsg);
	}
	return __super::PreTranslateMessage(pMsg);
}

void CRevisionGraphDlg::OnViewShowBranchingsMerges()
{
	m_Graph.m_bShowBranchingsMerges = ToggleSetMenu(L"ShowRevGraphBranchesMerges", ID_VIEW_SHOWBRANCHINGSANDMERGES);

	UpdateFullHistory();
}

void CRevisionGraphDlg::OnViewShowAllTags()
{
	m_Graph.m_bShowAllTags = ToggleSetMenu(L"ShowRevGraphAllTags", ID_VIEW_SHOWALLTAGS);

	UpdateFullHistory();
}

void CRevisionGraphDlg::OnViewArrowPointToMerges()
{
	m_Graph.m_bArrowPointToMerges = ToggleSetMenu(L"ArrowPointToMerges", ID_VIEW_ARROW_POINT_TO_MERGES);
	UpdateFullHistory();
}

void CRevisionGraphDlg::DoZoom (float zoom)
{
	m_fZoomFactor = zoom;
	m_Graph.DoZoom (zoom);
	UpdateZoomBox();
}

void CRevisionGraphDlg::OnViewZoomin()
{
	DoZoom (min (MAX_ZOOM, m_fZoomFactor / ZOOM_STEP));
}

void CRevisionGraphDlg::OnViewZoomout()
{
	DoZoom (max (MIN_ZOOM, m_fZoomFactor * ZOOM_STEP));
}

void CRevisionGraphDlg::OnViewZoom100()
{
	DoZoom (DEFAULT_ZOOM);
}

void CRevisionGraphDlg::OnViewZoomHeight()
{
	CRect graphRect = m_Graph.GetGraphRect();
	CRect windowRect = m_Graph.GetWindowRect();

	float horzfact = (windowRect.Width() - 4.0f)/(4.0f + graphRect.Width());
	float vertfact = (windowRect.Height() - 4.0f)/(4.0f + graphRect.Height());
	if ((horzfact < vertfact) && (horzfact < MAX_ZOOM))
		vertfact = (windowRect.Height() - CDPIAware::Instance().ScaleY(GetSafeHwnd(), 20)) / (4.0f + graphRect.Height());

	DoZoom (min (MAX_ZOOM, vertfact));
}

void CRevisionGraphDlg::OnViewZoomWidth()
{
	// zoom the graph so that it is completely visible in the window
	CRect graphRect = m_Graph.GetGraphRect();
	CRect windowRect = m_Graph.GetWindowRect();

	float horzfact = (windowRect.Width() - 4.0f)/(4.0f + graphRect.Width());
	float vertfact = (windowRect.Height() - 4.0f)/(4.0f + graphRect.Height());
	if ((vertfact < horzfact) && (vertfact < MAX_ZOOM))
		horzfact = (windowRect.Width() - CDPIAware::Instance().ScaleX(GetSafeHwnd(), 20)) / (4.0f + graphRect.Width());

	DoZoom (min (MAX_ZOOM, horzfact));
}

void CRevisionGraphDlg::OnViewZoomAll()
{
	// zoom the graph so that it is completely visible in the window
	CRect graphRect = m_Graph.GetGraphRect();
	CRect windowRect = m_Graph.GetWindowRect();

	float horzfact = (windowRect.Width() - 4.0f)/(4.0f + graphRect.Width());
	float vertfact = (windowRect.Height() - 4.0f)/(4.0f + graphRect.Height());

	DoZoom (min (MAX_ZOOM, min(horzfact, vertfact)));
}

void CRevisionGraphDlg::OnFind()
{
	if (!m_pFindDialog)
	{
		m_pFindDialog = new CFindDlg(this);
		m_pFindDialog->Create(this);
	}
	else
	{
		m_pFindDialog->SetFocus();
		return;
	}
}

LRESULT CRevisionGraphDlg::OnFindDialogMessage(WPARAM /*wParam*/, LPARAM /*lParam*/)
{
	ASSERT(m_pFindDialog);
	bool bFound = false;
	int i = 0;

	if (m_pFindDialog->IsTerminating())
	{
		// invalidate the handle identifying the dialog box.
		m_pFindDialog = nullptr;
		return 0;
	}

	bool bShift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
	int cnt = static_cast<int>(m_Graph.m_logEntries.size());
	if (m_pFindDialog->IsRef())
	{
		CString str;
		str = m_pFindDialog->GetFindString();

		CGitHash hash;

		if (!str.IsEmpty())
		{
			if (g_Git.GetHash(hash, str + L"^{}")) // add ^{} in order to get the correct SHA-1 (especially for signed tags)
				MessageBox(g_Git.GetGitLastErr(L"Could not get hash of ref \"" + str + L"^{}\"."), L"TortoiseGit", MB_ICONERROR);
		}

		if (!hash.IsEmpty())
		{
			for (i = 0; i < cnt; ++i)
			{
				if (m_Graph.m_logEntries.at(i) == hash)
				{
					bFound = true;
					break;
				}
			}
		}
		if (!bFound)
		{
			m_pFindDialog->FlashWindowEx(FLASHW_ALL, 2, 100);
			return 0;
		}
	}

	if (m_pFindDialog->FindNext() && !bFound)
	{
		//read data from dialog
		CLogDlgFilter filter{ m_pFindDialog->GetFindString(), m_pFindDialog->Regex(), LOGFILTER_SUBJECT | LOGFILTER_MESSAGES | LOGFILTER_AUTHORS | LOGFILTER_EMAILS | LOGFILTER_REVS | LOGFILTER_REFNAME, m_pFindDialog->MatchCase() == TRUE };

		for (i = m_nSearchIndex + 1;; ++i)
		{
			if (i >= cnt)
			{
				i = 0;
				m_pFindDialog->FlashWindowEx(FLASHW_ALL, 2, 100);
			}
			if (m_nSearchIndex >= 0)
			{
				if (i == m_nSearchIndex)
				{
					::MessageBeep(0xFFFFFFFF);
					m_pFindDialog->FlashWindowEx(FLASHW_ALL, 3, 100);
					break;
				}
			}

			if (filter(m_Graph.m_LogCache.GetCacheData(m_Graph.m_logEntries.at(i)), nullptr, m_Graph.m_HashMap))
			{
				bFound = true;
				break;
			}
		}
	} // if(m_pFindDialog->FindNext())

	if (bFound)
	{
		m_nSearchIndex = i;
		m_Graph.ScrollTo(i, !bShift);
		Invalidate(FALSE);
	}

	return 0;
}

void CRevisionGraphDlg::OnMenuexit()
{
	if (!m_Graph.IsUpdateJobRunning())
		EndDialog(IDOK);
}

void CRevisionGraphDlg::OnMenuhelp()
{
	OnHelp();
}

void CRevisionGraphDlg::OnViewCompareheadrevisions()
{
	m_Graph.CompareRevs(L"HEAD");
}

void CRevisionGraphDlg::OnViewComparerevisions()
{
	m_Graph.CompareRevs(L"");
}

void CRevisionGraphDlg::OnViewUnifieddiff()
{
	m_Graph.UnifiedDiffRevs(false);
}

void CRevisionGraphDlg::OnViewUnifieddiffofheadrevisions()
{
	m_Graph.UnifiedDiffRevs(true);
}

void CRevisionGraphDlg::UpdateFullHistory()
{
	m_bFetchLogs = true;
	Invalidate();
	StartWorkerThread();
}

void CRevisionGraphDlg::StartWorkerThread()
{
	if (!m_Graph.IsUpdateJobRunning())
		m_Graph.updateJob = std::make_unique<CFuture<bool>>(this, &CRevisionGraphDlg::UpdateData);
}

void CRevisionGraphDlg::OnCancel()
{
	if (!m_Graph.IsUpdateJobRunning())
		__super::OnCancel();
}

void CRevisionGraphDlg::OnOK()
{
	OnChangeZoom();
}

void CRevisionGraphDlg::OnFileSavegraphas()
{
	CString tempfile;
	int filterindex = 0;
	if (CAppUtils::FileOpenSave(tempfile, &filterindex, IDS_REVGRAPH_SAVEPIC, IDS_PICTUREFILEFILTER, false, m_hWnd))
	{
		// if the user doesn't specify a file extension, default to
		// svg and add that extension to the filename. But only if the
		// user chose the 'pictures' filter. The filename isn't changed
		// if the 'All files' filter was chosen.
		CString extension;
		int dotPos = tempfile.ReverseFind('.');
		int slashPos = tempfile.ReverseFind('\\');
		if (dotPos > slashPos)
			extension = tempfile.Mid(dotPos);
		if ((filterindex == 1)&&(extension.IsEmpty()))
		{
			extension = L".svg";
			tempfile += extension;
		}
		if ((filterindex == 2)&&(extension.IsEmpty()))
		{
			extension = L".gv";
			tempfile += extension;
		}
		m_Graph.SaveGraphAs(tempfile);
	}
}

CRect CRevisionGraphDlg::GetGraphRect()
{
	CRect rect;
	GetClientRect(&rect);

	CRect statusbarrect;
	m_StatusBar.GetClientRect(&statusbarrect);
	rect.bottom -= statusbarrect.Height();

	CRect toolbarrect;
	m_ToolBar.GetClientRect(&toolbarrect);
	rect.top += toolbarrect.Height();

	return rect;
}

void CRevisionGraphDlg::UpdateStatusBar()
{
//	CString sFormat;
//	sFormat.Format(IDS_REVGRAPH_STATUSBARURL, static_cast<LPCWSTR>(m_Graph.m_sPath));
//	m_StatusBar.SetText(sFormat,1,0);
//	sFormat.Format(IDS_REVGRAPH_STATUSBARNUMNODES, m_Graph.m_state.GetNodeCount());
//	m_StatusBar.SetText(sFormat,0,0);
}

void CRevisionGraphDlg::OnChangeZoom()
{
	if (!IsWindow(m_Graph.GetSafeHwnd()))
		return;
	CString strItem;
	auto pCBox = static_cast<CComboBoxEx*>(m_ToolBar.GetDlgItem(ID_REVGRAPH_ZOOMCOMBO));
	pCBox->GetWindowText(strItem);
	if (strItem.IsEmpty())
		return;

	DoZoom(static_cast<float>(_wtof(strItem) / 100.0));
}

void CRevisionGraphDlg::UpdateZoomBox()
{
	CString strText;
	CString strItem;
	auto pCBox = static_cast<CComboBoxEx*>(m_ToolBar.GetDlgItem(ID_REVGRAPH_ZOOMCOMBO));
	pCBox->GetWindowText(strItem);
	strText.Format(L"%.0f%%", (m_fZoomFactor * 100.0));
	if (strText.Compare(strItem) != 0)
		pCBox->SetWindowText(strText);
}

BOOL CRevisionGraphDlg::OnToolTipNotify(UINT /*id*/, NMHDR *pNMHDR, LRESULT *pResult)
{
	// need to handle both ANSI and UNICODE versions of the message
	auto pTTTA = reinterpret_cast<TOOLTIPTEXTA*>(pNMHDR);
	auto pTTTW = reinterpret_cast<TOOLTIPTEXTW*>(pNMHDR);
	CString strTipText;

	UINT_PTR nID = pNMHDR->idFrom;

	if (pNMHDR->code == TTN_NEEDTEXTA && (pTTTA->uFlags & TTF_IDISHWND) ||
		pNMHDR->code == TTN_NEEDTEXTW && (pTTTW->uFlags & TTF_IDISHWND))
	{
		// idFrom is actually the HWND of the tool
		nID = ::GetDlgCtrlID(reinterpret_cast<HWND>(nID));
	}

	if (nID != 0) // will be zero on a separator
		strTipText.LoadString (static_cast<UINT>(nID));

	*pResult = 0;
	if (strTipText.IsEmpty())
		return TRUE;

	if (strTipText.GetLength() >= MAX_TT_LENGTH)
		strTipText = strTipText.Left(MAX_TT_LENGTH);

	if (pNMHDR->code == TTN_NEEDTEXTA)
	{
		::SendMessage(pNMHDR->hwndFrom, TTM_SETMAXTIPWIDTH, 0, 600);
		pTTTA->lpszText = m_szTip;
		WideCharToMultiByte(CP_ACP, 0, strTipText, -1, m_szTip, strTipText.GetLength()+1, 0, 0);
	}
	else
	{
		::SendMessage(pNMHDR->hwndFrom, TTM_SETMAXTIPWIDTH, 0, 600);
		lstrcpyn(m_wszTip, strTipText, strTipText.GetLength()+1);
		pTTTW->lpszText = m_wszTip;
	}
	// bring the tooltip window above other pop up windows
	::SetWindowPos(pNMHDR->hwndFrom, HWND_TOP, 0, 0, 0, 0,
		SWP_NOACTIVATE|SWP_NOSIZE|SWP_NOMOVE|SWP_NOOWNERZORDER);
	return TRUE;	// message was handled
}

void CRevisionGraphDlg::OnViewFilter()
{
	CRevGraphFilterDlg dlg;

	dlg.m_bCurrentBranch = this->m_Graph.m_bCurrentBranch;
	dlg.m_bLocalBranches = m_Graph.m_bLocalBranches;
	dlg.SetRevisionRange(m_Graph.m_FromRev, m_Graph.m_ToRev);

	if (dlg.DoModal()==IDOK)
	{
		// user pressed OK to dismiss the dialog, which means
		// we have to accept the new filter settings and apply them

		dlg.GetRevisionRange(m_Graph.m_FromRev, m_Graph.m_ToRev);
		// update menu & toolbar

		this->m_Graph.m_bCurrentBranch = dlg.m_bCurrentBranch;
		m_Graph.m_bLocalBranches = dlg.m_bLocalBranches;

		CMenu * pMenu = GetMenu();
		int tbstate = m_ToolBar.GetToolBarCtrl().GetState(ID_VIEW_FILTER);
		if (m_Graph.m_bCurrentBranch || m_Graph.m_bLocalBranches || !m_Graph.m_FromRev.IsEmpty() || !m_Graph.m_ToRev.IsEmpty())
		{
			if (pMenu)
				pMenu->CheckMenuItem(ID_VIEW_FILTER, MF_BYCOMMAND | MF_CHECKED);
			m_ToolBar.GetToolBarCtrl().SetState(ID_VIEW_FILTER, tbstate | TBSTATE_CHECKED);
		}
		else
		{
			if (pMenu)
				pMenu->CheckMenuItem(ID_VIEW_FILTER, MF_BYCOMMAND | MF_UNCHECKED);
			m_ToolBar.GetToolBarCtrl().SetState(ID_VIEW_FILTER, tbstate & (~TBSTATE_CHECKED));
		}

		// re-run query

		StartWorkerThread();
	}
}

void CRevisionGraphDlg::OnViewShowoverview()
{
	m_Graph.SetShowOverview(ToggleSetMenu(L"ShowRevGraphOverview", ID_VIEW_SHOWOVERVIEW));

	m_Graph.Invalidate(FALSE);
}

void CRevisionGraphDlg::OnWindowPosChanging(WINDOWPOS* lpwndpos)
{
	if (!m_bVisible)
		lpwndpos->flags &= ~SWP_SHOWWINDOW;
	CResizableStandAloneDialog::OnWindowPosChanging(lpwndpos);
}

LRESULT CRevisionGraphDlg::OnDPIChanged(WPARAM wParam, LPARAM lParam)
{
	CDPIAware::Instance().Invalidate();
	m_ToolBar.CloseWindow();
	m_ToolBar.DestroyWindow();
	InitializeToolbar();
	return __super::OnDPIChanged(wParam, lParam);
}
