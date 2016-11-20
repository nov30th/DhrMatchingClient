
/*****************************************************
Copyright 1985-2010 QZJ
By Vincent.Qiu
nov30th@gmail.com
******************************************************/

// DhrMatchingUrlService.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "DhrMatchingUrlService.h"
#include "DhrMatchingUrlServiceDlg.h"
#include <Dbghelp.h>

/* if debug . no inline functions */ 
#ifdef _DEBUG
#pragma auto_inline (off)
#endif

#pragma comment( lib, "DbgHelp" )




#ifdef _DEBUG
#define new DEBUG_NEW
#endif

LONG WINAPI UEFilter(PEXCEPTION_POINTERS ExceptionInfo);

// CDhrMatchingUrlServiceApp

BEGIN_MESSAGE_MAP(CDhrMatchingUrlServiceApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CDhrMatchingUrlServiceApp construction

CDhrMatchingUrlServiceApp::CDhrMatchingUrlServiceApp()
{
	// support Restart Manager
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;

	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CDhrMatchingUrlServiceApp object

CDhrMatchingUrlServiceApp theApp;


// CDhrMatchingUrlServiceApp initialization

BOOL CDhrMatchingUrlServiceApp::InitInstance()
{
	HANDLE   m_hMutex=CreateMutex(NULL,FALSE, m_pszAppName);    

	if(GetLastError()==ERROR_ALREADY_EXISTS)   
	{   
		AfxMessageBox("The program has already been started!");   
		return FALSE;
	} 

	::SetUnhandledExceptionFilter(UEFilter);


	// InitCommonControlsEx() is required on Windows XP if an application
	// manifest specifies use of ComCtl32.dll version 6 or later to enable
	// visual styles.  Otherwise, any window creation will fail.
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// Set this to include all the common control classes you want to use
	// in your application.
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();

	if (!AfxSocketInit())
	{
		AfxMessageBox(IDP_SOCKETS_INIT_FAILED);
		return FALSE;
	}


	AfxEnableControlContainer();

	// Create the shell manager, in case the dialog contains
	// any shell tree view or shell list view controls.
	CShellManager *pShellManager = new CShellManager;

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	// of your final executable, you should remove from the following
	// the specific initialization routines you do not need
	// Change the registry key under which our settings are stored
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization
	SetRegistryKey(_T("Local AppWizard-Generated Applications"));

	CDhrMatchingUrlServiceDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with OK
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with Cancel
	}

	// Delete the shell manager created above.
	if (pShellManager != NULL)
	{
		delete pShellManager;
	}

	// Since the dialog has been closed, return FALSE so that we exit the
	// application, rather than start the application's message pump.
	return FALSE;
}

LONG WINAPI UEFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
	CString strFileName,m_packetRecordFilepath;
	char m_mydocument_path[MAX_PATH]   =   {0}; 
	SHGetSpecialFolderPath(NULL, m_mydocument_path, CSIDL_PERSONAL, FALSE);
	if (m_mydocument_path[0] == '\0')
	{
		AfxMessageBox("My Document path can not be found");
		exit(1);
	}
	m_packetRecordFilepath.Format("%s", m_mydocument_path);
	if (m_packetRecordFilepath.Right(1) != "\\")
		m_packetRecordFilepath += "\\";


	CTime t = CTime::GetCurrentTime(); 



	strFileName.Format("%s%s%s.dmp",m_packetRecordFilepath, "DirectHR_MC_Dump_File_",t.FormatGmt("%Y-%m-%d_%H%M%S_%W-%A"));

	HANDLE lhDumpFile = CreateFile(strFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL ,NULL);

	MINIDUMP_EXCEPTION_INFORMATION loExceptionInfo;

	loExceptionInfo.ExceptionPointers = ExceptionInfo;

	loExceptionInfo.ThreadId = GetCurrentThreadId();

	loExceptionInfo.ClientPointers = TRUE;

	MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),lhDumpFile, MiniDumpNormal, &loExceptionInfo, NULL, NULL);

	CloseHandle(lhDumpFile);

	AfxMessageBox("Matching Client crashed! Please report this problem to IT Team.");

	return EXCEPTION_EXECUTE_HANDLER;
} 

