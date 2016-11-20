
/*****************************************************
Copyright 1985-2010 QZJ
By Vincent.Qiu
nov30th@gmail.com
******************************************************/

// DhrMatchingUrlServiceDlg.cpp : implementation file
//
//#include "windows.h"
#include "stdafx.h"
#include "afxdialogex.h"
#include "PCAP.h"
#include "Iphlpapi.h"
#include "Mmsystem.h"

#include "DhrMatchingUrlService.h"
#include "DhrMatchingUrlServiceDlg.h"

#include "QzjConfLoader.h"
#include "QzjWinpcap.h"
#include "QzjHttpPost.h"


#pragma comment(lib,  "Packet")
#pragma comment(lib,  "wpcap")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "winmm.lib")



#ifdef _DEBUG
#define new DEBUG_NEW
#endif




//#define WM_QZJWINPCAP WM_USER+12
//#define QW_URL WM_USER+30
#define WM_DHRMATCHINGTRAY	WM_USER+5
//<--------------- IP datagram ------------------>
//++++++++++++++++++++++++++++++++++++++++++++++++
//|   IP    |  TCP    |          TCP             |
//| Header  | Header  |         Data             |
//++++++++++++++++++++++++++++++++++++++++++++++++
//20 bytes  20 bytes
//At-least  At-least

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Source Port          |       Destination Port        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Acknowledgment Number                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Data |           |U|A|P|R|S|F|                               |
// | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
// |       |           |G|K|H|T|N|N|                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Checksum            |         Urgent Pointer        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             data                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

HINSTANCE g_hInst;
HWND g_hWnd;
NOTIFYICONDATA nid;//taskbar icon

CQzjWinpcap qzjWinpcap;//QZJ winpcap module
CString selectedAdapterName;
PIP_ADAPTER_INFO pOrgAdapterInfo; //所有网络设备的列表
CWinThread* m_pWinThread;
CString m_postDataTo;
CString _username, _password;
unsigned int isHide = 2;
bool isRunning = false;

char m_mydocument_path[MAX_PATH]   =   {0}; 
UINT StartCapturing(LPVOID lParam);
INT_PTR CALLBACK MainDlgProc(HWND,UINT,WPARAM,LPARAM);

//*******************************************************************************************************
//MainDlgProc: 
//					Message processing.
//
//*******************************************************************************************************
INT_PTR CALLBACK MainDlgProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	switch(uMsg){
	case WM_INITDIALOG:
		{
			HICON hIcon=LoadIcon(g_hInst,MAKEINTRESOURCE(IDR_MAINFRAME));
			SendMessage(hDlg,WM_SETICON,ICON_BIG,(LPARAM)hIcon);
			SendMessage(hDlg,WM_SETICON,ICON_SMALL,(LPARAM)hIcon);
			//::Shell_NotifyIcon(NIM_ADD,&nid);
			//if(hIcon)
			//	::DestroyIcon(hIcon);

			SetDlgItemText(hDlg,IDD_DHRMATCHINGURLSERVICE_DIALOG,TEXT("Last Version - 2012.05.08"));
			return TRUE;
		}
	case WM_DHRMATCHINGTRAY:
		if(wParam==IDR_MAINFRAME){
			if(lParam==WM_LBUTTONDOWN){
				ShowWindow(hDlg,SW_SHOWNORMAL);
				return TRUE;
			}	
		}
		return FALSE;
	case WM_DESTROY:
		Shell_NotifyIcon(NIM_DELETE,&nid);
		return TRUE;
	case WM_SYSCOMMAND:
		switch(wParam)
		{
		case SC_CLOSE:
			DestroyWindow(hDlg);
			PostQuitMessage(0);
			return TRUE;
		case SC_MINIMIZE:
			ShowWindow(g_hWnd,SW_HIDE);
			Shell_NotifyIcon(NIM_ADD,&nid);
			return TRUE;
		}
	}
	return FALSE;
}


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

LRESULT CDhrMatchingUrlServiceDlg::OnTrayIconClick(WPARAM wParam,LPARAM lParam)
{
	if(wParam==IDR_MAINFRAME){
		if(lParam==WM_LBUTTONDOWN){
			ShowWindow(SW_SHOWNORMAL);
			return TRUE;
		}
	}
	return FALSE;
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)

END_MESSAGE_MAP()


// CDhrMatchingUrlServiceDlg dialog


CDhrMatchingUrlServiceDlg::CDhrMatchingUrlServiceDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CDhrMatchingUrlServiceDlg::IDD, pParent)
	, m_serverIp(_T(""))
	, m_serverStatus(_T(""))
	, m_lastUrl(_T(""))
	, m_urlCount(_T(""))
	, m_errorCount(_T(""))
	, m_largepackets(_T(""))
	, m_logbox(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_serverIp = _T("");
	m_packetsQueued = _T("");
	//  m_username = _T("");
}

CDhrMatchingUrlServiceDlg::~CDhrMatchingUrlServiceDlg()
{
	Shell_NotifyIcon(NIM_DELETE,&nid);
}



void CDhrMatchingUrlServiceDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_NETWORKADAPTER, m_networkAdapterDropdown);
	DDX_Control(pDX, IDC_LIST_STATUS, m_statusList);
	DDX_Control(pDX, IDC_EDIT_PASSWORD, m_inputPassword);
	DDX_Control(pDX, IDC_EDIT_USERNAME, m_inputUsername);
	DDX_Control(pDX, IDC_BTN_LOGIN, m_btnLogin);
	DDX_Control(pDX, IDC_CHECKBEEP, m_chkBeep);
}

BEGIN_MESSAGE_MAP(CDhrMatchingUrlServiceDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_CBN_SELCHANGE(IDC_NETWORKADAPTER, &CDhrMatchingUrlServiceDlg::OnCbnSelchangeNetworkadapter)
	ON_MESSAGE(WM_DHRMATCHINGTRAY,&CDhrMatchingUrlServiceDlg::OnTrayIconClick)
	ON_MESSAGE(WM_QZJWINPCAP,&CDhrMatchingUrlServiceDlg::OnQzjWinpcapMessage)
	ON_BN_CLICKED(IDOK, &CDhrMatchingUrlServiceDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_BTN_LOGIN, &CDhrMatchingUrlServiceDlg::OnBnClickedBtnLogin)
	ON_BN_CLICKED(IDC_BTNHIDEWINDOW, &CDhrMatchingUrlServiceDlg::OnBnClickedBtnhidewindow)
	ON_BN_CLICKED(IDC_BTNCLEANADAPTER, &CDhrMatchingUrlServiceDlg::OnBnClickedBtncleanadapter)
END_MESSAGE_MAP()

//*******************************************************************************************************
//OnInitDialog: 
//					初始窗口同时加载配置文件, 网卡列表, 任务栏图标.
//
//*******************************************************************************************************
// CDhrMatchingUrlServiceDlg message handlers
BOOL CDhrMatchingUrlServiceDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	confFile.Load();
	//设置窗口标题
	SetWindowTextA("DHR Matching Client " + confFile.LocalFileVersion);

	SHGetSpecialFolderPath(NULL, m_mydocument_path, CSIDL_PERSONAL, FALSE);
	if (m_mydocument_path[0] == '\0')
	{
		AfxMessageBox("My Document path can not be found");
		exit(1);
	}

	GetAdaptersToList();
	//Get the username from config file.

	m_inputUsername.SetWindowTextA(confFile.LoginUsername);
	/*******Add icon to taskbar ****/
	g_hWnd = this->m_hWnd;
	nid.cbSize = sizeof(NOTIFYICONDATA);
	nid.hWnd = this->m_hWnd;
	nid.uID = IDR_MAINFRAME;
	nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;		
	nid.uCallbackMessage = WM_DHRMATCHINGTRAY;	
	nid.hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_QZJERROR));
	CString directTip = "DIRECT HR MATCHING CLIENT";
	strcpy_s(nid.szTip, directTip.GetLength() + 1,directTip);
	//在托盘区添加图标
	Shell_NotifyIcon(NIM_ADD,&nid);

	//如果当前网卡正常工作且有默认用户名，则直接使用此网卡和当前用户后台登录
	if (isRunning && !confFile.LoginUsername.IsEmpty())
	{
		OnBnClickedBtnLogin(); 
		//设置isHde为0，标示启动时隐藏窗口
		isHide = 0;
	}

	return FALSE;  // return TRUE  unless you set the focus to a control
}

void CDhrMatchingUrlServiceDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		switch(nID)
		{
		case SC_MINIMIZE:
		case SC_CLOSE:
			ShowWindow(SW_HIDE);
			return;
		case WM_QUIT:
			return;
		}
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

//*******************************************************************************************************
//InitTray: 
//					Add icon to tray.
//
//*******************************************************************************************************
void CDhrMatchingUrlServiceDlg::InitTray()
{
	::Shell_NotifyIcon(NIM_ADD,&nid);
	//if(g_hInst)
	//	::DestroyIcon(g_hInst);
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.
void CDhrMatchingUrlServiceDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();

		//1.仅当网卡唯一且用户名不为空(此时自动登录)时IsHide初始值为0
		//2.系统运行时，会加载两次OnPaint函数，第一次绘制窗体，第二次绘制窗体内容
		//3.只有满足2,3条件时isHide才有可能不大于1
		//4.当isHide不大于1时，隐藏窗口
		if(isHide <= 1)
			ShowWindow(SW_HIDE);
		isHide ++;
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CDhrMatchingUrlServiceDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//*******************************************************************************************************
//GetAdaptersToList: 
//					Get adapters list from local system. By using Winpcap module.
//					m_networkAdapterDropdown will be fill with adapters information.
//*******************************************************************************************************
void CDhrMatchingUrlServiceDlg::GetAdaptersToList()
{

	m_networkAdapterDropdown.ResetContent();
	PIP_ADAPTER_INFO pAdapterInfo = NULL;
	ULONG ulLen = 0;
	unsigned int i=0;
	//Alloc memory to adapters
	::GetAdaptersInfo(pAdapterInfo,&ulLen);
	pAdapterInfo = (PIP_ADAPTER_INFO)::GlobalAlloc(GPTR, ulLen);

	//Get local adapters information
	if(::GetAdaptersInfo(pAdapterInfo,&ulLen) ==  ERROR_SUCCESS)
	{
		pOrgAdapterInfo = pAdapterInfo;
		while(pAdapterInfo != NULL)
		{
			m_networkAdapterDropdown.InsertString(i,pAdapterInfo->Description);

			char adaptername[100];
			strcpy_s(adaptername,"\\Device\\NPF_");
			strcat_s(adaptername,pAdapterInfo->AdapterName);
			strcpy_s(pAdapterInfo->AdapterName,adaptername);
			if (strstr(pAdapterInfo->IpAddressList.IpAddress.String,"172.") == pAdapterInfo->IpAddressList.IpAddress.String
				|| strstr(pAdapterInfo->IpAddressList.IpAddress.String,"192.168.1.") == pAdapterInfo->IpAddressList.IpAddress.String
				)
			{
				SelectDefaultAdapter(i);
			}
			else if(adaptername == confFile.DefaultNetWorkAdapter)
			{
				SelectDefaultAdapter(i);
			}
			pAdapterInfo = pAdapterInfo->Next;
			i++;
		}
	}
	//如果当前只有一个网卡，则默认选中该网卡
	if(i == 1)
	{
		SelectDefaultAdapter(i - 1);
	}
}
//*******************************************************************************************************
//SelectAdapterAndStartCap: 
//					Set the adapter to capture and start the capturing process.
//
//*******************************************************************************************************

void CDhrMatchingUrlServiceDlg::SelectDefaultAdapter(int currentSelect)
{
	m_networkAdapterDropdown.SetCurSel(currentSelect);
	OnCbnSelchangeNetworkadapter();
	m_inputUsername.EnableWindow(true);
	m_btnLogin.EnableWindow(true);
}
void CDhrMatchingUrlServiceDlg::SelectAdapterAndStartCap(CString adapterName)
{
	AddMessageToListBox("Getting Adapter Information..");
	PIP_ADAPTER_INFO pAdapterInfo = pOrgAdapterInfo;
	//设置当前选中的网卡为工作网卡
	while(pAdapterInfo->Description != adapterName && pAdapterInfo->AdapterName != adapterName)
		pAdapterInfo = pAdapterInfo->Next;
	qzjWinpcap.SetAdapter(pAdapterInfo->AdapterName);
	AddMessageToListBox("Setting Adapter Information..");
	//设置网卡连接日志文件名
	qzjWinpcap.SetPacketRecordFilename("Log.txt");
	//设置日志文件保存路径
	qzjWinpcap.SetPacketRecordFilePath(m_mydocument_path);
	//创建日志文件
	if(qzjWinpcap.PrepareUrlMonitor(this->m_hWnd)<0)
	{
		AfxMessageBox("Can not open this network adapter!",MB_OK,-1);
		isRunning = false;
		((CComboBox*)GetDlgItem(IDC_NETWORKADAPTER))->EnableWindow(true);
		m_networkAdapterDropdown.SetCurSel(-1);
		return;
	}

	//测试网络连接
	if (confFile.GetFilters()<0)
	{
		AfxMessageBox("Cannot connect to the Internet.",MB_OK,-1);
		this->EndDialog(-1);
		exit(-1);
	}
	//测试过滤配置文件是否加载
	if (qzjWinpcap.SetFilters(confFile.FiltersContent.GetBuffer())<=0)
	{
		confFile.FiltersContent.ReleaseBuffer();
		AfxMessageBox("Can not load the fileters from Server!",MB_OK,-1);
		this->EndDialog(-1);
		exit(-1);
	}
	confFile.FiltersContent.ReleaseBuffer();
	m_postDataTo = confFile.ServerPostAddress;

	m_pWinThread = AfxBeginThread(StartCapturing,(LPVOID)selectedAdapterName.GetBuffer(),THREAD_PRIORITY_NORMAL,0,0,0);
	AddMessageToListBox("Monitor Begin..");
	selectedAdapterName.ReleaseBuffer();

	if(pAdapterInfo->AdapterName != confFile.DefaultNetWorkAdapter)
	{
		//项配置文件中写入默认网卡
		confFile.SetDefaultNetWorkAdapter(pAdapterInfo->AdapterName);
	}
	//标示程序正在运行
	isRunning = true;

	m_inputUsername.EnableWindow(true);
	m_btnLogin.EnableWindow(true);
}

//*******************************************************************************************************
//OnCbnSelchangeNetworkadapter: 
//					event for adapter changed or selected
//
//*******************************************************************************************************
void CDhrMatchingUrlServiceDlg::OnCbnSelchangeNetworkadapter()
{
	// 选中网卡后开始工作
	UpdateData(true);
	((CComboBox*)GetDlgItem(IDC_NETWORKADAPTER))->EnableWindow(false);
	CString m_adaptername;
	m_networkAdapterDropdown.GetLBText(m_networkAdapterDropdown.GetCurSel(),m_adaptername);
	//开启网卡连接
	SelectAdapterAndStartCap(m_adaptername);
}

//*******************************************************************************************************
//OnQzjWinpcapMessage: 
//					Once packets has been Analyzed. Winpcap	status messages will be received here.
//
//*******************************************************************************************************
LRESULT CDhrMatchingUrlServiceDlg::OnQzjWinpcapMessage(WPARAM wParam,LPARAM lParam)
{
	static ULONG ulong_urlCount = 0, ulong_packets = 0, ulong_error = 0, ulong_large = 0;
	static ULONG ulong_queted = 0, ulong_regrouped = 0;
	static char *pChar = NULL;
	switch(wParam){
	case QW_URL:
		{
			/*	nid.hIcon=LoadIcon(AfxGetInstanceHandle(),MAKEINTRESOURCE(IDI_QZJUPLOAD));
			::Shell_NotifyIcon(NIM_MODIFY,&nid);*/
			m_lastUrl.Format("%s",lParam);
			m_urlCount.Format("%d",++ulong_urlCount);
			CQzjHttpPost post;
			CString sHeaderSend="", sHeaderReceive="", sMessage="";
			sHeaderSend.Format("%s",lParam);
			sHeaderSend.Replace("[QZJ]POSTER[/QZJ]",_username);
			try
			{
				post.SendRequest(true, m_postDataTo, sHeaderSend, sHeaderReceive, sMessage);
			}
			catch(...)
			{
				MakeSound("ERROR");
				//更新错误图标
				nid.hIcon=LoadIcon(AfxGetInstanceHandle(),MAKEINTRESOURCE(IDI_QZJERROR));
			}
			if(sMessage == "True")
			{
				MakeSound("OK");
				//更新正确图标
				nid.hIcon=LoadIcon(AfxGetInstanceHandle(),MAKEINTRESOURCE(IDI_QZJCORRECT));
			}
			else
			{
				MakeSound("WARNING");
				//更新错误图标
				nid.hIcon=LoadIcon(AfxGetInstanceHandle(),MAKEINTRESOURCE(IDI_QZJERROR));
			}
			::Shell_NotifyIcon(NIM_MODIFY,&nid);
			break;
		}
	case QW_PACKET:
		{
			m_serverStatus.Format("%d",++ulong_packets);
			break;
		}
	case QW_ERROR:
		{
			CStdioFile file;
			CString errorlog = qzjWinpcap.GetRecordFilepath() + "Error_Log.txt";
			file.Open(errorlog,CFile::modeCreate|CFile::modeNoTruncate|CFile::modeReadWrite);
			if(file == NULL)
			{
				AfxMessageBox("Can't open ERROR.log");
			}
			else
			{
				file.SeekToEnd();
				file.Write((char*)lParam,strlen((char*)lParam));
				file.Close();
				m_errorCount.Format("%d",++ulong_error);
			}
			break;
		}
	case QW_REGROUPED:
		{
			m_largepackets.Format("%d",++ulong_regrouped);
			break;
		}
	case QW_QUEUED:
		{
			m_packetsQueued.Format("%d",++ulong_queted);
			break;
		}
	case QW_PACKETTOOLARGE:
		{

		}
	default:
		{
			return -1;
		}
	}
	UpdateData(false);
	return 0;
}

//*******************************************************************************************************
//OnQzjWinpcapMessage: 
//					Once packets has been Analyzed. Winpcap	status messages will be received here.
//
//*******************************************************************************************************
UINT StartCapturing(LPVOID lParam)
{
	int retval = qzjWinpcap.Packet_Loop();
	CString retString;
	retString.Format("%d",retval);
	return retval;
}


UINT StartSending(LPVOID lParam)
{
	CQzjHttpPost post;
	CString sHeaderSend, sHeaderReceive, sMessage;
	post.SendRequest(false, (char*)lParam, sHeaderSend, sHeaderReceive, sMessage);

	return 0;
}


void CDhrMatchingUrlServiceDlg::OnBnClickedOk() 
{
	if (AfxMessageBox("Are you sure you want to close this application?\r\nIf you end this program, the resume search result will not be sent out.",
		MB_OKCANCEL|MB_ICONQUESTION) != 1)
		return;
	CDialogEx::OnOK(); 
}

//*******************************************************************************************************
//AddMessageToListBox: 
//					Add message To ListBox
//
//*******************************************************************************************************
void CDhrMatchingUrlServiceDlg::AddMessageToListBox(CString message)
{
	m_statusList.InsertString(m_statusList.GetCount(), message);
}
//*******************************************************************************************************
//OnBnClickedBtnLogin: 
//					Event when login button was clicked.
//					Set the m_inputUsername as uploader.
//*******************************************************************************************************
void CDhrMatchingUrlServiceDlg::OnBnClickedBtnLogin()
{
	CString btnText = "";
	m_btnLogin.GetWindowTextA(btnText);
	//if(btnText == "Log Out")
	//{
	//	AddMessageToListBox("Log Out succeed!");
	//	m_inputUsername.EnableWindow(true);
	//	((CComboBox*)GetDlgItem(IDC_NETWORKADAPTER))->EnableWindow(true);
	//	m_btnLogin.SetWindowTextA("Log In");
	//}
	/*else
	{*/
	m_inputUsername.GetWindowTextA(_username);
	if(_username.IsEmpty())
	{
		AfxMessageBox("Please input Username!");
	}
	else if (!isRunning)
	{
		AfxMessageBox("Please choose a network adapter!");
	}
	else
	{
		((CComboBox*)GetDlgItem(IDC_NETWORKADAPTER))->EnableWindow(false);
		m_inputUsername.EnableWindow(false);
		m_btnLogin.EnableWindow(false);
		/*m_btnLogin.SetWindowTextA("Log Out");*/

		//更新config文件里的用户名
		if(confFile.LoginUsername != _username)
		{
			confFile.SetUsername(_username);
		}
		nid.hIcon = LoadIcon(AfxGetInstanceHandle(),MAKEINTRESOURCE(IDI_QZJUPLOAD));
		::Shell_NotifyIcon(NIM_MODIFY,&nid);
		AddMessageToListBox("Log In succeed!");
	}
	//}
}
void CDhrMatchingUrlServiceDlg::OnBnClickedBtnhidewindow()
{
	ShowWindow(SW_HIDE);
}

//*******************************************************************************************************
//MakeSound: 
//					Make noise!
//					szMessageType values: ERROR,OK,WARNING
//*******************************************************************************************************
void CDhrMatchingUrlServiceDlg::MakeSound(CString szMessageType)
{
	if (m_chkBeep.GetCheck() !=0)
	{
		if (szMessageType=="ERROR")
			PlaySound("ERROR.wav ", NULL, SND_NOWAIT);
		else if (szMessageType=="OK")
			PlaySound("OK.wav ", NULL, SND_NOWAIT);
		else if  (szMessageType=="WARNING")
			PlaySound("WARNING.wav ", NULL, SND_NOWAIT);
	}
}


void CDhrMatchingUrlServiceDlg::OnBnClickedBtncleanadapter()
{
	// TODO: 在此添加控件通知处理程序代码
}
