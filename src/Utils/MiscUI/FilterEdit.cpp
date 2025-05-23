﻿// TortoiseGit - a Windows shell extension for easy version control

// Copyright (C) 2023-2025 - TortoiseGit
// Copyright (C) 2007, 2009, 2011-2015, 2017-2020, 2022 - TortoiseSVN

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
#include "FilterEdit.h"
#include "LoadIconEx.h"
#include "Theme.h"
#include "ClipboardHelper.h"

const UINT CFilterEdit::WM_FILTEREDIT_INFOCLICKED = ::RegisterWindowMessage(L"TGITWM_FILTEREDIT_INFOCLICKED");
const UINT CFilterEdit::WM_FILTEREDIT_CANCELCLICKED = ::RegisterWindowMessage(L"TGITWM_FILTEREDIT_CANCELCLICKED");

IMPLEMENT_DYNAMIC(CFilterEdit, CEdit)

CFilterEdit::CFilterEdit()
	: m_backColor(CTheme::Instance().IsDarkTheme() ? CTheme::darkBkColor : GetSysColor(COLOR_WINDOW))
{
	m_themeCallbackId = CTheme::Instance().RegisterThemeChangeCallback([this]() { SetTheme(CTheme::Instance().IsDarkTheme()); });
	SetTheme(CTheme::Instance().IsDarkTheme());
}

CFilterEdit::~CFilterEdit()
{
	CTheme::Instance().RemoveRegisteredCallback(m_themeCallbackId);
}

BEGIN_MESSAGE_MAP(CFilterEdit, CEdit)
	ON_WM_SETFOCUS()
	ON_MESSAGE(WM_SETFONT, OnSetFont)
	ON_WM_SIZE()
	ON_WM_ERASEBKGND()
	ON_WM_KEYDOWN()
	ON_WM_LBUTTONDOWN()
	ON_WM_LBUTTONUP()
	ON_WM_CREATE()
	ON_WM_SETCURSOR()
	ON_CONTROL_REFLECT_EX(EN_CHANGE, &CFilterEdit::OnEnChange)
	ON_WM_CTLCOLOR_REFLECT()
	ON_WM_PAINT()
	ON_CONTROL_REFLECT(EN_KILLFOCUS, &CFilterEdit::OnEnKillfocus)
	ON_CONTROL_REFLECT(EN_SETFOCUS, &CFilterEdit::OnEnSetfocus)
	ON_MESSAGE(WM_PASTE, &CFilterEdit::OnPaste)
	ON_WM_THEMECHANGED()
END_MESSAGE_MAP()



// CFilterEdit message handlers

void CFilterEdit::PreSubclassWindow( )
{
	// We must have a multi line edit
	// to be able to set the edit rect
	ASSERT( GetStyle() & ES_MULTILINE );

	ResizeWindow();
}

BOOL CFilterEdit::PreTranslateMessage( MSG* pMsg )
{
	return CEdit::PreTranslateMessage(pMsg);
}

ULONG CFilterEdit::GetGestureStatus(CPoint /*ptTouch*/)
{
	return 0;
}

BOOL CFilterEdit::SetCancelBitmaps(UINT uCancelNormal, UINT uCancelPressed, int cx96dpi, int cy96dpi, BOOL bShowAlways)
{
	m_bShowCancelButtonAlways = bShowAlways;

	m_hIconCancelNormal = LoadDpiScaledIcon(uCancelNormal, cx96dpi, cy96dpi);
	m_hIconCancelPressed = LoadDpiScaledIcon(uCancelPressed, cx96dpi, cy96dpi);

	if (!m_hIconCancelNormal || !m_hIconCancelPressed)
		return FALSE;

	m_sizeCancelIcon = GetIconSize(m_hIconCancelNormal);

	ResizeWindow();
	return TRUE;
}

BOOL CFilterEdit::SetInfoIcon(UINT uInfo, int cx96dpi, int cy96dpi)
{
	m_hIconInfo = LoadDpiScaledIcon(uInfo, cx96dpi, cy96dpi);

	if (!m_hIconInfo)
		return FALSE;

	m_sizeInfoIcon = GetIconSize(m_hIconInfo);

	ResizeWindow();
	return TRUE;
}

BOOL CFilterEdit::SetCueBanner(LPCWSTR lpcwText)
{
	if (lpcwText)
	{
		m_sCueBanner = lpcwText;
		InvalidateRect(nullptr, TRUE);
		return TRUE;
	}
	m_sCueBanner.Empty();
	InvalidateRect(nullptr, TRUE);
	return FALSE;
}

void CFilterEdit::ResizeWindow()
{
	if (!::IsWindow(m_hWnd))
		return;

	CRect editrc, rc;
	GetRect(&editrc);
	GetClientRect(&rc);
	editrc.left = rc.left + 4;
	editrc.top = rc.top + 1;
	editrc.right = rc.right - 4;
	editrc.bottom = rc.bottom - 4;

	CWindowDC dc(this);
	HGDIOBJ oldFont = dc.SelectObject(GetFont()->GetSafeHandle());
	TEXTMETRIC tm = { 0 };
	dc.GetTextMetrics(&tm);
	dc.SelectObject(oldFont);

	m_rcEditArea.left = editrc.left + m_sizeInfoIcon.cx;
	m_rcEditArea.right = editrc.right - m_sizeCancelIcon.cx - 5;
	m_rcEditArea.top = (rc.Height() - tm.tmHeight) / 2;
	m_rcEditArea.bottom = m_rcEditArea.top + tm.tmHeight;

	m_rcButtonArea.left = m_rcEditArea.right + 5;
	m_rcButtonArea.right = rc.right;
	m_rcButtonArea.top = (((rc.bottom)-m_sizeCancelIcon.cy)/2);
	m_rcButtonArea.bottom = m_rcButtonArea.top + m_sizeCancelIcon.cy;

	m_rcInfoArea.left = 0;
	m_rcInfoArea.right = m_rcEditArea.left;
	m_rcInfoArea.top = (((rc.bottom)-m_sizeInfoIcon.cy)/2);
	m_rcInfoArea.bottom = m_rcInfoArea.top + m_sizeInfoIcon.cy;

	SetRect(&m_rcEditArea);
}

void CFilterEdit::SetButtonClickedMessageId(UINT iButtonClickedMessageId, UINT iCancelClickedMessageId)
{
	m_iButtonClickedMessageId = iButtonClickedMessageId;
	m_iCancelClickedMessageId = iCancelClickedMessageId;
}

CSize CFilterEdit::GetIconSize(HICON hIcon)
{
	CSize size(0, 0);
	ICONINFO iconinfo;
	if (GetIconInfo(hIcon, &iconinfo))
	{
		BITMAP bmp;
		if (GetObject(iconinfo.hbmColor, sizeof(BITMAP), &bmp))
		{
			size.cx = bmp.bmWidth;
			size.cy = bmp.bmHeight;
		}
		DeleteObject(iconinfo.hbmColor);
		DeleteObject(iconinfo.hbmMask);
	}
	return size;
}

BOOL CFilterEdit::OnEraseBkgnd(CDC* pDC)
{
	RECT rc;
	GetClientRect(&rc);
	pDC->FillSolidRect(&rc, m_backColor);

	if (GetWindowTextLength() || m_bShowCancelButtonAlways)
	{
		if (!m_bPressed)
		{
			DrawIconEx(pDC->GetSafeHdc(), m_rcButtonArea.left, m_rcButtonArea.top, m_hIconCancelNormal,
				m_sizeCancelIcon.cx, m_sizeCancelIcon.cy, 0, nullptr, DI_NORMAL);
		}
		else
		{
			DrawIconEx(pDC->GetSafeHdc(), m_rcButtonArea.left, m_rcButtonArea.top, m_hIconCancelPressed,
				m_sizeCancelIcon.cx, m_sizeCancelIcon.cy, 0, nullptr, DI_NORMAL);
		}
	}
	if (m_hIconInfo)
	{
		DrawIconEx(pDC->GetSafeHdc(), m_rcInfoArea.left, m_rcInfoArea.top, m_hIconInfo,
			m_sizeInfoIcon.cx, m_sizeInfoIcon.cy, 0, nullptr, DI_NORMAL);
	}

	return TRUE;
}

void CFilterEdit::OnLButtonUp(UINT nFlags, CPoint point)
{
	m_bPressed = FALSE;
	InvalidateRect(nullptr);
	if (m_rcButtonArea.PtInRect(point))
	{
		SetWindowText(L"");
		CWnd *pOwner = GetOwner();
		if (pOwner)
		{
			pOwner->SendMessage(m_iCancelClickedMessageId, reinterpret_cast<WPARAM>(GetSafeHwnd()), 0);
		}
		Validate();
	}
	if (m_rcInfoArea.PtInRect(point))
	{
		CWnd *pOwner = GetOwner();
		if (pOwner)
		{
			RECT rc = m_rcInfoArea;
			ClientToScreen(&rc);
			pOwner->SendMessage(m_iButtonClickedMessageId, reinterpret_cast<WPARAM>(GetSafeHwnd()), reinterpret_cast<LPARAM>(&rc));
		}
	}

	CEdit::OnLButtonUp(nFlags, point);
}

void CFilterEdit::OnLButtonDown(UINT nFlags, CPoint point)
{
	m_bPressed = m_rcButtonArea.PtInRect(point);
	//InvalidateRect(nullptr);
	CEdit::OnLButtonDown(nFlags, point);
}

int CFilterEdit::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CEdit::OnCreate(lpCreateStruct) == -1)
		return -1;

	ResizeWindow();

	return 0;
}

LRESULT CFilterEdit::OnSetFont( WPARAM wParam, LPARAM lParam )
{
	DefWindowProc( WM_SETFONT, wParam, lParam );

	ResizeWindow();

	return 0;
}

void CFilterEdit::OnSetFocus(CWnd* pOldWnd)
{
	__super::OnSetFocus(pOldWnd);
	if (auto len = GetWindowTextLength(); len > 0)
		SetSel(0, len);
}

void CFilterEdit::OnSize( UINT nType, int cx, int cy )
{
	CEdit::OnSize( nType, cx, cy );
	ResizeWindow();
}

BOOL CFilterEdit::OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message)
{
	CPoint pntCursor;
	GetCursorPos(&pntCursor);
	ScreenToClient(&pntCursor);
	// if the cursor is not in the edit area, show the normal arrow cursor
	if (!m_rcEditArea.PtInRect(pntCursor))
	{
		SetCursor(AfxGetApp()->LoadStandardCursor(IDC_ARROW));
		return TRUE;
	}

	return CEdit::OnSetCursor(pWnd, nHitTest, message);
}

BOOL CFilterEdit::OnEnChange()
{
	// check whether the entered text is valid
	Validate();
	InvalidateRect(nullptr);
	return FALSE;
}

HBRUSH CFilterEdit::CtlColor(CDC* pDC, UINT /*nCtlColor*/)
{
	if (m_backColor != (CTheme::Instance().IsDarkTheme() ? CTheme::darkBkColor : GetSysColor(COLOR_WINDOW)))
	{
		pDC->SetBkColor(m_backColor);
		return m_brBack;
	}
	return nullptr;
}

LRESULT CFilterEdit::OnThemeChanged()
{
	ResizeWindow();
	return 0;
}

void CFilterEdit::Validate()
{
	if (m_pValidator)
	{
		CString text;
		GetWindowText(text);
		m_backColor = CTheme::Instance().IsDarkTheme() ? CTheme::darkBkColor : GetSysColor(COLOR_WINDOW);
		if (!m_pValidator->Validate(text))
		{
			// Use a background color slightly shifted to red.
			// We do this by increasing red component and decreasing green and blue.
			const int SHIFT_PERCENTAGE = 10;
			int r = GetRValue(m_backColor);
			int g = GetGValue(m_backColor);
			int b = GetBValue(m_backColor);

			r = min(r * (100 + SHIFT_PERCENTAGE) / 100, 255);
			// Ensure that there is at least some redness.
			r = max(r, 255 * SHIFT_PERCENTAGE / 100);
			g = g * (100 - SHIFT_PERCENTAGE) / 100;
			b = b * (100 - SHIFT_PERCENTAGE) / 100;
			m_backColor = RGB(r, g, b);
			m_brBack.DeleteObject();
			m_brBack.CreateSolidBrush(m_backColor);
		}
	}
}

void CFilterEdit::OnPaint()
{
	LRESULT defres = Default();

	DrawDimText();
	if (defres)
	{
		// the Default() call did not process the WM_PAINT message!
		// Validate the update region ourselves to avoid
		// an endless loop repainting
		CRect rc;
		GetUpdateRect(&rc, FALSE);
		if (!rc.IsRectEmpty())
			ValidateRect(rc);
	}

	return;
}

void CFilterEdit::DrawDimText()
{
	if (m_sCueBanner.IsEmpty())
		return;
	if (GetWindowTextLength())
		return;
	if (GetFocus() == this)
		return;

	CClientDC	dcDraw(this);
	int			iState = dcDraw.SaveDC();

	dcDraw.SelectObject((*GetFont()));
	dcDraw.SetTextColor(CTheme::Instance().GetThemeColor(GetSysColor(COLOR_GRAYTEXT)));
	dcDraw.SetBkColor(CTheme::Instance().IsDarkTheme() ? CTheme::darkBkColor : GetSysColor(COLOR_WINDOW));
	dcDraw.DrawText(m_sCueBanner, m_sCueBanner.GetLength(), &m_rcEditArea, DT_CENTER | DT_VCENTER);
	dcDraw.RestoreDC(iState);
	return;
}

HICON CFilterEdit::LoadDpiScaledIcon(UINT resourceId, int cx96dpi, int cy96dpi)
{
	CWindowDC dc(this);
	int cx = MulDiv(cx96dpi, dc.GetDeviceCaps(LOGPIXELSX), 96);
	int cy = MulDiv(cy96dpi, dc.GetDeviceCaps(LOGPIXELSY), 96);
	return LoadIconEx(AfxGetResourceHandle(), MAKEINTRESOURCE(resourceId), cx, cy);
}

void CFilterEdit::SetTheme(bool /*bDark*/)
{
	Validate();
}

void CFilterEdit::OnEnKillfocus()
{
	InvalidateRect(nullptr);
}

void CFilterEdit::OnEnSetfocus()
{
	InvalidateRect(nullptr);
}

LRESULT CFilterEdit::OnPaste(WPARAM, LPARAM)
{
	CClipboardHelper clipboardHelper;
	if (clipboardHelper.Open(nullptr))
	{
		CString toInsert;
		HGLOBAL hglb = GetClipboardData(CF_TEXT);
		if (hglb)
		{
			LPCSTR lpstr = static_cast<LPCSTR>(GlobalLock(hglb));
			toInsert = CString(lpstr);
			GlobalUnlock(hglb);
		}
		hglb = GetClipboardData(CF_UNICODETEXT);
		if (hglb)
		{
			LPCWSTR lpstr = static_cast<LPCWSTR>(GlobalLock(hglb));
			toInsert = lpstr;
			GlobalUnlock(hglb);
		}

		// elimate control chars, especially newlines
		toInsert.Replace(L'\t', L' ');

		// only insert first line
		toInsert.Replace(L'\r', L'\n');
		int pos = 0;
		toInsert = toInsert.Tokenize(L"\n", pos);
		toInsert.Trim();

		// get the current text
		CString text;
		GetWindowText(text);

		// construct the new text
		int from, to;
		GetSel(from, to);
		text.Delete(from, to - from);
		text.Insert(from, toInsert);
		from += toInsert.GetLength();

		// update & notify controls
		SetWindowText(text);
		SetSel(from, from, FALSE);
		SetModify(TRUE);

		GetParent()->SendMessage(WM_COMMAND, MAKEWPARAM(GetDlgCtrlID(), EN_CHANGE), reinterpret_cast<LPARAM>(GetSafeHwnd()));
	}

	return 0;
}
