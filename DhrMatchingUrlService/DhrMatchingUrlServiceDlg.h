
/*****************************************************
Copyright 1985-2010 QZJ
Direct HR Matching Client
By Vincent.Qiu
nov30th@gmail.com
******************************************************/
// DhrMatchingUrlServiceDlg.h : header file
//

#pragma once
#include "QzjConfLoader.h"

// CDhrMatchingUrlServiceDlg dialog
class CDhrMatchingUrlServiceDlg : public CDialogEx
{
// Construction
public:
	CDhrMatchingUrlServiceDlg(CWnd* pParent = NULL);	// standard constructor
	~CDhrMatchingUrlServiceDlg();
// Dialog Data
	enum { IDD = IDD_DHRMATCHINGURLSERVICE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;
	void InitTray();
	void GetAdaptersToList();
	void SelectDefaultAdapter(int currentSelect);
	void SelectAdapterAndStartCap(CString adapterName);
	void MakeSound(CString szMessageType);
	LRESULT OnTrayIconClick(WPARAM wParam,LPARAM lParam);
	LRESULT OnQzjWinpcapMessage(WPARAM wParam,LPARAM lParam);
	void AddMessageToListBox(CString message);
	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
//	CString m_ipAddress;
//	CString m_serverPort;
	CString m_serverStatus;
	CQzjConfLoader confFile;
	CString m_lastUrl;
	CString m_urlCount;
	CString m_errorCount;
	CString m_serverIp;
	CComboBox m_networkAdapterDropdown;
	//afx_msg void OnBnClickedButton1();
	afx_msg void OnCbnSelchangeNetworkadapter();
	afx_msg void OnBnClickedOk();
	CString m_largepackets;
	CString m_packetsQueued;
	//afx_msg void OnBnClickedButton2();
	CString m_logbox;
	CListBox m_statusList;
	afx_msg void OnBnClickedBtnLogin();
//	CEdit m_inputUsername;
	CEdit m_inputPassword;
//	afx_msg void OnEnChangeEditPassword();
//	CString m_username;
	CEdit m_inputUsername;
	afx_msg void OnBnClickedBtnhidewindow();
	CButton m_btnLogin;
	CButton m_chkBeep;
	afx_msg void OnBnClickedBtncleanadapter();
};
