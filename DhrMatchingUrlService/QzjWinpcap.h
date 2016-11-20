/*****************************************************
Copyright 1985-2010 QZJ
Socket IP TCP HTTP
Filter
Created At:2010.9.17
By Vincent.Qiu
nov30th@gmail.com
******************************************************/

#pragma once

#define WM_QZJWINPCAP WM_USER+12
#define QW_URL WM_USER+30
#define QW_POSTDATA WM_USER+36
#define QW_ERROR WM_USER+31
#define QW_PACKET WM_USER+32
#define QW_REGROUPED WM_USER+33
#define QW_QUEUED WM_USER+34
#define QW_PACKETTOOLARGE WM_USER+35

#define POST "POST"
#define MAXPACKETSIZE 80000
#define URL_LENGTH_LIMIATION 4096
#define HOST_LENGTH_LIMIATION 200
#define MAXQUEUE 30

class CQzjWinpcap
{


protected:
	CString m_selectedAdapter;
	CString m_packetRecordFilename;
	BOOL m_promisc;
	FILE *m_recordFile;


public:
	CString m_packetRecordFilepath;
	CQzjWinpcap(void);
	~CQzjWinpcap(void);
	int SetFilter(char *name, char* url, char* host, bool isPost);
	int SetFilters(char* filters);
	int RemoveAllFilters();
	UINT Packet_Loop();
	void SetAdapter(CString adapter);
	CString GetSelectedAdapterNpf();
	void SetPacketRecordFilename(CString filename);
	CString GetPacketRecordFilename();
	long PrepareUrlMonitor(LPVOID lpParam);
	int SetPacketRecordFilePath(char *filepath);
	CString GetRecordFilepath();
};

