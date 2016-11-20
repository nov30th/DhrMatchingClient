#pragma once

class CQzjConfLoader
{
private:
	CString m_configFilename;
public:
	CQzjConfLoader(void);
	~CQzjConfLoader(void);
	CString ServerPostAddress;
	CString ServerFilterAddress;
	CString FiltersContent;
	CString LocalFileVersion;
	CString LoginUsername;
	CString DefaultNetWorkAdapter;
	CString GetUsernameFromReg(void);
	int SetUsername(CString username);
	int SetDefaultNetWorkAdapter(CString adapterName);
	int GetFilters(void);
	int Load(void);
};

