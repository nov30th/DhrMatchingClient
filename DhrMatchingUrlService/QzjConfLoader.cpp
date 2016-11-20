#include "StdAfx.h"
#include "QzjConfLoader.h"
#include "QzjHttpPost.h"

CQzjConfLoader::CQzjConfLoader(void)
{
	CString des = "";
	TCHAR mydocument_folder[255] = {0};
	SHGetSpecialFolderPath(NULL, mydocument_folder, CSIDL_PERSONAL, FALSE);
//	::GetCurrentDirectory(1024,des.GetBuffer(1024));
	strcat_s(mydocument_folder,"\\MatchingClientConfig.ini");
	m_configFilename.Format("%s",mydocument_folder);
}


CQzjConfLoader::~CQzjConfLoader(void)
{
}


int CQzjConfLoader::Load(void)
{
	//��ȡ�����ļ�
	GetPrivateProfileString("Server","PostAddress","",ServerPostAddress.GetBufferSetLength(1024),1024,m_configFilename);
	ServerPostAddress.ReleaseBuffer();
	GetPrivateProfileString("Server","FilterAddress","",ServerFilterAddress.GetBufferSetLength(1024),1024,m_configFilename);
	ServerFilterAddress.ReleaseBuffer();
	GetPrivateProfileString("Version","LocalFileVersion","",LocalFileVersion.GetBufferSetLength(1024),1024,m_configFilename);
	ServerFilterAddress.ReleaseBuffer();
	GetPrivateProfileString("Login","Username","",LoginUsername.GetBufferSetLength(1024),1024,m_configFilename);
	LoginUsername.ReleaseBuffer();
	CString Username = GetUsernameFromReg();
	if (LoginUsername.GetLength() <=0)
		LoginUsername = Username;
	GetPrivateProfileString("DefaultNetWorkAdapter","AdapterName","",DefaultNetWorkAdapter.GetBufferSetLength(1024),1024,m_configFilename);
	DefaultNetWorkAdapter.ReleaseBuffer();

	if (ServerPostAddress.GetLength() <=0)
		ServerPostAddress = "http://matchengine.directhr.net/DataReceiver/SaveSearchResult.ashx";

	if (ServerFilterAddress.GetLength() <=0)
		ServerFilterAddress = "http://matchengine.directhr.net/matching.txt";

	return 0;
}

CString CQzjConfLoader::GetUsernameFromReg(void)
{
	HKEY hKey;
	LONG nResult = 0;
	DWORD dwSize = 0;    // ���ݳ���

	TCHAR lpSubKey[] = _T("Environment");
	TCHAR lpValueName[] = _T("DHR_Username");

	///////////////

	nResult = RegOpenKeyEx(HKEY_CURRENT_USER,    // ����
		lpSubKey,    // �Ӽ�
		NULL,
		KEY_READ,    // Ȩ��
		&hKey);        // Handle

	if( nResult != ERROR_SUCCESS )
	{
		return NULL;
	}

	///////////////////

	// ��һ�ε��ã���ȡ���ݳ���
	RegQueryValueEx(hKey,
		lpValueName,
		NULL,
		NULL,
		NULL,
		&dwSize);            // ����������

	if (dwSize <= 0)
		return NULL;

	// ��̬���仺����
	LPBYTE dataBuf = new BYTE[dwSize];

	// �ڶ��ε��ã���ȡ����
	RegQueryValueEx(hKey,
		lpValueName,
		NULL,
		NULL,
		dataBuf,
		&dwSize);

	// �ر�
	RegCloseKey(hKey);

	CString retval;
	retval.Format("%s",dataBuf);

	// �ͷŻ�����
	delete[] dataBuf;
	return retval;
}


int CQzjConfLoader::SetUsername(CString username)
{
	WritePrivateProfileString("Login","Username",username,m_configFilename);
	return 0;
}

int CQzjConfLoader::SetDefaultNetWorkAdapter(CString adapterName)
{
	WritePrivateProfileString("DefaultNetWorkAdapter","AdapterName",adapterName,m_configFilename);
	return 0;
}

int CQzjConfLoader::GetFilters(void)
{
	CString sHeaderSend, sHeaderReceive;
	CQzjHttpPost post;
	post.SendRequest(false, (LPCTSTR)_T(ServerFilterAddress), sHeaderSend, sHeaderReceive, FiltersContent);

	if (FiltersContent.GetLength() <= 0)
		return -1;
	/************************************
	[Filter]
	[Host]www.host.com[/Host]
	[Url]/aaa.asp?fjeijfiejfi[/Url]
	[Post]False[/Post]
	[/Filter]
	[Filter]
	[Host]www.host1.com[/Host]
	[Url]/bbb.asp?fjeijfiejfi[/Url]
	[Post]True[/Post]
	[/Filter]
	************************************/
	return 0;
}
