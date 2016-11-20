/*****************************************************
Copyright 1985-2010 QZJ
Winpcap IP TCP HTTP
Post packet regroup & fetch function
including get packet
By Vincent.Qiu
nov30th@gmail.com
******************************************************/

#include "StdAfx.h"
#include "QzjWinpcap.h"
#include "PCAP.h"
#include "IPTypes.h"

#define NODEBUGINFO

void Packet_Handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
CString DateTimeNow();
void SendFinalData(char *ma_host, char *ma_method, char *ma_postData, char *ma_url, char *ma_cookie, int filterId);
int AddPacketToQueue(const struct pcap_pkthdr* header, const u_char* pkt_data,u_int32_t ackNumber);
void ProcessData(char* httpContent, bool isLaragePacket);
int FilterPacket(char* method, char* host, char* url);


enum{ 
	MAC_ADDR_LEN  = 6,
	IP_ADDR_LEN   = 4
};
enum{
	ETH_TYPE  =  0x0806,
	IP_TYPE =    0x0800 
};

typedef struct MAH_t
{
	char *data;	//memory space for chars
	char *ma_host;		//host address, the domain
	char *ma_url;		//Path
	char *ma_method;	//method of the http request
	char *ma_postData;	//the point of the post data begin
	char *ma_cookie;	//cookies sent
	u_int32_t ackNumber;//ACK number of the TCP connection
	u_int totalLength;
	u_int postLength;
	u_int currentPostLen;
};


typedef struct
{
	MAH_t *pMah_t[MAXQUEUE];
	unsigned int currentLogin;
	unsigned int count;

}MahList_t,*pMahList_t;

typedef struct 
{
	unsigned char  eh_dst[MAC_ADDR_LEN];    //以太网目的地址
	unsigned char  eh_src[MAC_ADDR_LEN];    //以太网源地址
	unsigned short eh_type;                 //以太网类型，默认0x0806
	char           data[1];
}ETH_t, *pETH_t;

typedef struct 
{
	u_int8_t ip_verhl;      /* version & header length */
	u_int8_t ip_tos;        /* type of service */
	u_int16_t ip_len;       /* datagram length */
	u_int16_t ip_id;        /* identification  */
	u_int16_t ip_off;       /* fragment offset */
	u_int8_t ip_ttl;        /* time to live field */
	u_int8_t ip_proto;      /* datagram protocol */
	u_int16_t ip_csum;      /* checksum */
	struct in_addr ip_src;  /* source IP */
	struct in_addr ip_dst;  /* dest IP */
	char data[1];		/* TCP Header */
}IPH_t, *pIPH_t;

typedef struct
{
	u_int16_t th_sport;     /* source port */
	u_int16_t th_dport;     /* destination port */
	u_int32_t th_seq;       /* sequence number */
	u_int32_t th_ack;       /* acknowledgement number */
	u_int8_t th_offx2;     /* offset and reserved */
	u_int8_t th_flags;
#define    TH_FIN    0x01
#define    TH_SYN    0x02
#define    TH_RST    0x04
#define    TH_PSH    0x08
#define    TH_ACK    0x10
#define    TH_URG    0x20
	u_int16_t th_win;       /* window */
	u_int16_t th_sum;       /* checksum */
	u_int16_t th_urp;       /* urgent pointer */
	char data[1];
}TCPH_t, *pTCPH_t;

pMahList_t g_postQueue;
PIP_ADAPTER_INFO pAdapterInfo;//network adapter list
char m_error[PCAP_ERRBUF_SIZE];//winpcap error chars
pcap_t *pfp;//network adapter handler
FILE *m_urlFile;//the file which record the url for debugging
HWND hSendBackHwnd;//the message which hwnd will receive once url got
bool isStarted = false;
FILE *pfilter;
CString urlFilePath;

char FilterName[MAXQUEUE][HOST_LENGTH_LIMIATION];
char FilterHosts[MAXQUEUE][HOST_LENGTH_LIMIATION];
char FilterUrl[MAXQUEUE][URL_LENGTH_LIMIATION];
bool FilterMethodPost[MAXQUEUE];

CQzjWinpcap::CQzjWinpcap(void)
{

}
//*******************************************************************************************************
//~CQzjWinpcap: 
//					Clean all the memory of queues.   
//
//*******************************************************************************************************
CQzjWinpcap::~CQzjWinpcap(void)
{
	isStarted = false;	
	if (m_urlFile != NULL)
		fclose(m_urlFile);
	if (g_postQueue==NULL)
		return;

	for(int i = 1;i < MAXQUEUE;i ++)
	{
		free(g_postQueue->pMah_t[i-1]->data);
		free(g_postQueue->pMah_t[i-1]);
	}
	free(g_postQueue->pMah_t);
	//	free(g_postQueue);	

}
//*******************************************************************************************************
//GetSelectedAdapterNpf: 
//					Get the selected network adapter.
//
//*******************************************************************************************************
CString CQzjWinpcap::GetSelectedAdapterNpf()
{
	return m_selectedAdapter;
}

void CQzjWinpcap::SetAdapter(CString adapter)
{
	m_selectedAdapter = adapter;
}


CString CQzjWinpcap::GetPacketRecordFilename()
{
	return m_packetRecordFilename;
}

void CQzjWinpcap::SetPacketRecordFilename(CString filename)
{
	m_packetRecordFilename = filename;
}


CString DateTimeNow()
{
	CTime theTime = CTime::GetCurrentTime();
	return theTime.Format("%Y-%b-%d %H:%M:%S ");;
}

//*******************************************************************************************************
//PrepareUrlMonitor: 
//					Prepare the info of local comptuer adapters, filters before capture.
//
//*******************************************************************************************************
long CQzjWinpcap::PrepareUrlMonitor(LPVOID lpParam)
{
	hSendBackHwnd = (HWND)lpParam;
	if (m_selectedAdapter.GetLength() == 0)
		return -1;

	urlFilePath = m_packetRecordFilepath + "Url_" + m_packetRecordFilename;

	if ( fopen_s(&m_recordFile,m_packetRecordFilepath + "NetWorkAdapter_" + m_packetRecordFilename,"a+") <0)
	{
		if ( fopen_s(&m_recordFile,m_packetRecordFilepath + "NetWorkAdapter_"  + m_packetRecordFilename,"w+") <0)
			return -2001;
	}
	else
	{
		fputs("======================",m_recordFile);
		fputs(">>>>>>>>QZJWINPCAP DATA DEBUG<<<<<<<<<\r\n",m_recordFile);
		fputs(DateTimeNow(),m_recordFile);
		fputs(" INFO: QzjWinpcap Module started.\r\n",m_recordFile);
		fflush(m_recordFile);
	}

	//Get the network adapter list
	pAdapterInfo = NULL;
	ULONG ulLen = 0;
	::GetAdaptersInfo(pAdapterInfo,&ulLen);
	pAdapterInfo = (PIP_ADAPTER_INFO)::GlobalAlloc(GPTR, ulLen);
	if(::GetAdaptersInfo(pAdapterInfo,&ulLen) ==  ERROR_SUCCESS)
	{
		fputs(DateTimeNow(),m_recordFile);
		fputs(" DEBUG INFO: All adapter list below,\r\n",m_recordFile);
		PIP_ADAPTER_INFO pOrgAdapterInfo = pAdapterInfo;
		while(pAdapterInfo != NULL)
		{
			fputs(pAdapterInfo->Description,m_recordFile);
			fputs("\r\n--> ",m_recordFile);
			fputs(pAdapterInfo->AdapterName,m_recordFile);
			fputs("\r\n",m_recordFile);
			pAdapterInfo = pAdapterInfo->Next;
			fflush(m_recordFile);
		}
	}
	else
	{
	}


	//Open the network adapter
	if((pfp = pcap_open_live(m_selectedAdapter,MAXPACKETSIZE * sizeof(char),0,1,m_error)) == NULL )
	{
		fputs(DateTimeNow(),m_recordFile);
		fputs(" ERROR: Can not open the network adapter:",m_recordFile);
		fputs(m_selectedAdapter,m_recordFile);
		fclose(m_recordFile);
		return -1;
	}
	else
	{
		fputs(DateTimeNow(),m_recordFile);
		fputs(" INFO: Network adapter was opened by QzjWinpcap:",m_recordFile);
		fputs(m_selectedAdapter,m_recordFile);
		fputs("\r\n",m_recordFile);
		fflush(m_recordFile);
	}

	//Network adapter was opened by QzjWinpcap
	fputs(DateTimeNow(),m_recordFile);
	fputs(" INFO: Network adapter was opened by QzjWinpcap.\r\n",m_recordFile);
	fflush(m_recordFile);
	//Setting filters
	u_int netmask=0xffffff;//Netmask
	char packet_filter[] = "tcp dst port 80";//Filter condition
	struct bpf_program fcode;

	if (pcap_compile(pfp, &fcode, packet_filter, 1, netmask) < 0)
	{
		fputs(DateTimeNow(),m_recordFile);
		fputs(" ERROR: Compile filters error.\r\n",m_recordFile);
		fclose(m_recordFile);
		return -1;
	}
	else
	{
		fputs(DateTimeNow(),m_recordFile);
		fputs(" INFO: Compile filters done.\r\n",m_recordFile);
		fflush(m_recordFile);
	}

	//set the filter
	if (pcap_setfilter(pfp, &fcode) < 0)
	{
		fputs(DateTimeNow(),m_recordFile);
		fputs(" ERROR: Set filter error.\r\n",m_recordFile);
		fclose(m_recordFile);
		return -1;
	}
	else
	{
		fputs(DateTimeNow(),m_recordFile);
		fputs(" INFO: Set filter done.\r\n",m_recordFile);
		fflush(m_recordFile);
	}

	fputs(DateTimeNow(),m_recordFile);
	fputs(" INFO: Starting capture...\r\n",m_recordFile);
	fclose(m_recordFile);


	return 0;
}

//*******************************************************************************************************
//Packet_Loop: 
//					Capture packet.
//
//*******************************************************************************************************
UINT CQzjWinpcap::Packet_Loop()
{
	if (pfp == NULL)
		return -1;

	if(g_postQueue == NULL)
	{
		g_postQueue = (MahList_t*) malloc(sizeof(MahList_t)*MAXQUEUE);
	}

	MAH_t *pMah_t = (MAH_t*) malloc(sizeof(MAH_t));
	MAH_t *pOrgMah_t;
	pMah_t->data = (char*)malloc(MAXPACKETSIZE * sizeof(char));
	g_postQueue->pMah_t[0] = pMah_t;
	g_postQueue->count=1;
	g_postQueue->currentLogin = 0;

	for(int i=2;i<MAXQUEUE;i++)
	{
		pOrgMah_t  = pMah_t;
		if ((pMah_t = (MAH_t*) malloc(sizeof(MAH_t)))==NULL)
		{
			SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_ERROR,(LPARAM)"Alloc Memory to MAH failed!");
			exit(-1);
		}
		if ((pMah_t->data = (char*) malloc(MAXPACKETSIZE * sizeof(char)))==NULL)
		{
			SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_ERROR,(LPARAM)"Alloc Memory to MAh->Data failed!");
			exit(-1);
		}
		g_postQueue->pMah_t[i-1] = pMah_t;
		g_postQueue->count++;
	}

	//SET CALLBACK FUNCATION HERE!
	isStarted = true;
	pcap_loop(pfp, 0, Packet_Handler, NULL);
	return 0;
}
//*******************************************************************************************************
//Packet_Handler: 
//					Event func for one packet arrived in Winpcap queue.
//
//*******************************************************************************************************
void Packet_Handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	/* Packet must large (equ) than 80 and less than 20480*/
	if (isStarted == false)
		return;

	if (header->len < sizeof(IPH_t) + sizeof(TCPH_t) + 10 || header->len >=MAXPACKETSIZE -2)
	{
		//SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_PACKET,(LPARAM)NULL);
		return;
	}

	if (header->caplen > header->len)
	{
#ifndef NODEBUGINFO
		char temp[MAXPACKETSIZE * sizeof(char)];
		sprintf_s(temp,"%s%s%s%s","\r\n",DateTimeNow(),"GET-header-len-ERROR:", "caplen larger than len");
		SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_ERROR,(LPARAM)temp);
#endif
		return;
	}

	unsigned long
		HttpRequest=0 , 
		AcceptRequest=0 ,
		OtherPacket=0, 
		PiecePacket=0, 
		SpecPacket=0 ;

	char *httpContent = NULL;
	pETH_t pEr;
	pIPH_t pIph;                              
	pTCPH_t pTcph;
	pEr = (pETH_t)pkt_data ;
	pIph = (pIPH_t)pEr->data;
	pTcph = (pTCPH_t)pIph->data;

	/* TCP flag can be ACK or PSH&ACK */
	if ((pTcph->th_flags & (TH_ACK | TH_PSH ) )== 0||( pTcph->th_flags & TH_ACK )== 0)
	{
		/* NO HTTP PACKET FOUND */
		//SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_PACKET,(LPARAM)NULL);
		return;
	}

	httpContent = (char*)pkt_data;
	httpContent[header->caplen] = '\0';
	httpContent = pTcph->data;
	//if (httpContent[0] == 1)
	//{
	//	httpContent += 13;
	//}

	/* Length not enough for http content */
	if (header->caplen <= (unsigned int)( pTcph->data - (char*) pkt_data))
	{
#ifndef NODEBUGINFO
		char temp[MAXPACKETSIZE * sizeof(char)];
		sprintf_s(temp,"%s%s%s%s","\r\n",DateTimeNow(),"GET-HTTP-CONTENT-ERROR:", "Length not enough for http content");//pTcph->data);
		SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_ERROR,(LPARAM)temp);
#endif
		return;
	}


	/* CHECK THE DATA IF IT IS POST SUB PACKET */
	//MAH_t* pRegroupTCPMah_t = g_postQueue->pMah_t;

	unsigned int ip = g_postQueue->currentLogin + 1;
	while(g_postQueue->currentLogin != ip)   // pRegroupTCPMah_t->next != g_postQueue->pMah_t)
	{
		if ((++ip) == g_postQueue->count)
			ip = 0;
		if (pTcph->th_ack == g_postQueue->pMah_t[ip]->ackNumber)
		{
			if ((u_int)(header->caplen) + g_postQueue->pMah_t[ip]->totalLength >= MAXPACKETSIZE)
			{
#ifndef NODEBUGINFO
				SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_PACKETTOOLARGE,(LPARAM)NULL);
#endif
				return;
			}
			g_postQueue->pMah_t[ip]->totalLength += header->caplen;
			strcat_s(g_postQueue->pMah_t[ip]->data,MAXPACKETSIZE - 1,httpContent);
			g_postQueue->pMah_t[ip]->currentPostLen += strlen(httpContent);
			if (g_postQueue->pMah_t[ip]->currentPostLen >= g_postQueue->pMah_t[ip]->postLength)
				ProcessData( g_postQueue->pMah_t[ip]->data, true);
			//if ((pTcph->th_flags & TH_PSH) != 0)
			//{
			//	ProcessData( g_postQueue->pMah_t[ip]->data, true);//PUSH in TCP FLAG
			//}
			//else
			//{
			//	SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_QUEUED,(LPARAM)NULL);
			//}
			//return;
		}
	}

	char *ma_secondPara = NULL;
	if (( ma_secondPara = strstr(httpContent,"\r\n")) == NULL)
	{
		/* NO HTTP PACKET FOUND */
		//SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_PACKET,(LPARAM)NULL);
		return;
	}

	/* HTTP data first letter */
	char *szget=NULL,*szpost=NULL;
	if (( szget = strstr(httpContent, "GET ")) == NULL )
	{
		if (( szpost = strstr(httpContent, "POST ")) == NULL)
			return;
	}


	if (szpost == NULL || szget > szpost)
	{
		if ((pTcph->th_flags & TH_PSH) != 0)
			ProcessData( szget, false);//PUSH in TCP FLAG
		else
			AddPacketToQueue(header,(const u_char*)szget, pTcph->th_ack);//NO PUSH in TCP FLAG
	}
	else if(szget == NULL || szpost > szget)
	{
		/*******************
		Add post method packet to Queue
		Post content equ to content length, process anyway.
		********************/
		if (AddPacketToQueue(header,(const u_char*)szpost, pTcph->th_ack)==1);
		ProcessData(szpost, false);//DO process if has content
	}
	return;

	///////////////////////////////////
	/////////////////////////////////// 
	//DEBUG PACKET*********************
	///////////////////////////////////
	///////////////////////////////////
	//fputs("v------------------------v",m_urlFile);
	//fputs(httpContent,m_urlFile);
	//fputs("^------------------------^",m_urlFile);



}


//*******************************************************************************************************
//ProcessData: 
//					Event for http content packet is found.
//
//*******************************************************************************************************
void ProcessData(char* httpContent, bool isFinalPostData)
{
	//pETH_t pEr;
	//pIPH_t pIph;                              
	//pTCPH_t pTcph;
	//pEr = (pETH_t)pkt_data ;
	//pIph = (pIPH_t)pEr->data;
	//pTcph = (pTCPH_t)pIph->data;
	/* VAR */
	char *ma_url = NULL, *ma_host = NULL, *ma_method = httpContent, *ma_postData = NULL, *ma_cookie = NULL;

	//Split the HOST and URL and METHOD of the HTTP
	char *str_UrlB, *str_UrlE;

	if (strlen(httpContent)<=40)
		return;

	if ( (str_UrlB = strstr(httpContent," ")) !=NULL && (bpf_u_int32)(str_UrlB - httpContent + 1) < strlen(httpContent) && (str_UrlE = strstr(str_UrlB + 1," ")) !=NULL)
	{
		char *pHostBegin=NULL, *pCookieBegin = NULL, *pPostDataBegin = NULL;
		pCookieBegin = strstr(str_UrlE+1,"\r\nCookie:");
		pHostBegin = strstr(str_UrlE+1,"\r\nHost:");
		pPostDataBegin = strstr(str_UrlE+1,"\r\n\r\n");
		int subDataLeng = 4;

		if(pPostDataBegin == NULL)
		{
			pPostDataBegin = strstr(str_UrlE+1,"\r\n__EVENTTARGET");
			subDataLeng = 2;
		}
		/* Get the path of the http request to*/
		//URL//
		*str_UrlB = *str_UrlE = '\0';
		ma_url = str_UrlB + 1;
		/* Mark the post data position of the http request */
		//POST DATA//
		if (strcmp(ma_method,"POST")==0)
			if (pPostDataBegin!=NULL)
				ma_postData = pPostDataBegin + 4;

		//COOKIE//
		char *szCookieE= NULL;
		if (pCookieBegin!=NULL)
		{
			//Cookie found!
			ma_cookie = pCookieBegin;
			if (( szCookieE = strstr(pCookieBegin+1,"\r\n"))!=NULL)
			{
				*szCookieE = '\0';
			}
		}

		/* Get the Host string position of the http request */
		char *szHostE= NULL;
		if (pHostBegin !=NULL)
		{
			if ((szHostE = strstr(pHostBegin + 8,"\r\n")) !=NULL)
				*szHostE = '\0';
			ma_host = pHostBegin + 8;
		} 
		else
		{
			/* NO HOST WAS FOUND */
#ifndef NODEBUGINFO
			CString str_Error ="\r\n" +  DateTimeNow() + "GET-HOST-DATA-ERROR METHOD:" + ma_method +" HOST:" + ma_host +  " URL:" + ma_url;
			SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_ERROR,(LPARAM)str_Error.GetBuffer());
			str_Error.ReleaseBuffer();
#endif
			return;
		}
	}
	else
	{
		return;
	}

	if (ma_host == NULL || ma_method == NULL|| ma_url == NULL)
	{
#ifndef NODEBUGINFO
		CString str_Error ="\r\n" +  DateTimeNow() + "GET-DATA-NULL-ERROR METHOD:" + ma_method +" HOST:" + ma_host +  " URL:" + ma_url;
		SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_ERROR,(LPARAM)str_Error.GetBuffer());
		str_Error.ReleaseBuffer();
#endif
		return;
	}

	int filterId = FilterPacket(ma_method, ma_host, ma_url);
	if (filterId >= 0)
		SendFinalData(ma_host,ma_method,ma_postData,ma_url,ma_cookie,filterId);
}

//*******************************************************************************************************
//FilterPacket: 
//					Whether the packet fit for the filter
//
//*******************************************************************************************************
int FilterPacket(char* method, char* host, char* url)
{
	int i = 0;
	//_strupr_s(host,sizeof(char)*HOST_LENGTH_LIMIATION);
	while(i <MAXQUEUE && FilterHosts[i][0] !=0)
	{
		if ( strcmp(method,"POST")==0 && FilterMethodPost[i]
		||
			strcmp(method ,"POST")!=0 && !FilterMethodPost[i])
			if (strcmp(host ,FilterHosts[i])==0) 
				if (strstr(url,FilterUrl[i]) != NULL )
					return i;
		i++;
	}
	return -1;
}

//*******************************************************************************************************
//AddPacketToQueue: 
//					Add pieces of packet together
//Return Value: -1: Can not detect post data.
//				0: Post data has been deteccted.
//				1: Packet contains whole post data.(Completed packet)
//
//Last Modified: Vincent Qiu 2010.05.04
//*******************************************************************************************************
int AddPacketToQueue(const struct pcap_pkthdr* header, const u_char* httpContent, u_int32_t ackNumber)
{
	MAH_t *pMah_t;

	pMah_t = (MAH_t*) g_postQueue->pMah_t[g_postQueue->currentLogin];
	if (g_postQueue->currentLogin + 1 >= g_postQueue->count)
		g_postQueue->currentLogin = 0;

	memcpy_s(pMah_t->data,header->caplen + 1,httpContent,header->caplen + 1);
	pMah_t->totalLength = header->caplen;

	pMah_t->ackNumber = ackNumber;
	pMah_t->totalLength = header->len;

	char *b_content_length,*e_content_length;

	if (NULL == (b_content_length = strstr((char*)httpContent, "Content-Length: ")) || NULL == (e_content_length = strstr(b_content_length, "\r\n")))
	{
#ifndef NODEBUGINFO
		CString str_Error ="\r\n" +  DateTimeNow() + "GET-POST-LENGTG-ERROR CONTENT:" + (char*)httpContent;
		SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_ERROR,(LPARAM)str_Error.GetBuffer());
		str_Error.ReleaseBuffer();
#endif
		return -1;
	}

	b_content_length += 16;
	u_int u_contentLength;
	sscanf(b_content_length,"%u",&u_contentLength);
	pMah_t->postLength = u_contentLength;

	if (NULL == (b_content_length = strstr((char*)httpContent, "\r\n\r\n"))
		||
		*(b_content_length + 4) == '\0')
		pMah_t->currentPostLen = 0;
	else
		pMah_t->currentPostLen = strlen(b_content_length);
	*e_content_length = '\n';

	if (pMah_t->currentPostLen >= pMah_t->postLength && pMah_t->postLength > 0 )
		return 1;
	else
		return 0;
}

//*******************************************************************************************************
//SendFinalData: 
//					Send formatted message to message processing function.
//
//*******************************************************************************************************
void SendFinalData(char *ma_host, char *ma_method, char *ma_postData, char *ma_url, char *ma_cookie, int filterId)
{
	/* DATA VERIFIED */
	if (strlen(ma_url)>=URL_LENGTH_LIMIATION)
	{
#ifndef NODEBUGINFO
		CString str_Error = "\r\n" + DateTimeNow() + "URL-TOO-LONG-ERROR METHOD:" + ma_method +" HOST:" + ma_host +  " URL:" + ma_url;
		SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_ERROR,(LPARAM)str_Error.GetBuffer());
		str_Error.ReleaseBuffer();
#endif
		return;
	}

	try{

		if (fopen_s(&m_urlFile, urlFilePath,"a+") <0)
		{
			fopen_s(&m_urlFile,urlFilePath,"w+");
		}
		if(m_urlFile != 0x00000000)
		{
			//写日志文件
			fputs( DateTimeNow() + "GET-DATA-SUCCESS READY TO SEND...", m_urlFile);
			fclose(m_urlFile);
		}
	}
	catch(...)
	{

	}

	CString tempStr;
	//格式化httpRequest内容
	tempStr.Format("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\r\n<Matching version=\"1.0\">\r\n<ClientDataItem version=\"1.0\">\r\n<Poster>[QZJ]POSTER[/QZJ]</Poster>\r\n<Type><![CDATA[%s]]></Type>\r\n<Method><![CDATA[%s]]></Method>\r\n<Host><![CDATA[%s]]></Host>\r\n<Url><![CDATA[%s]]></Url>\r\n<Cookie><![CDATA[%s]]></Cookie>\r\n<PostData><![CDATA[%s]]></PostData>\r\n</ClientDataItem>\r\n</Matching>\r\n",
		FilterName[filterId],ma_method,ma_host,ma_url,ma_cookie,ma_postData);

	//向系统发送消息
	SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_URL,(LPARAM)tempStr.GetBuffer());
	tempStr.ReleaseBuffer();

	try{

		if (fopen_s(&m_urlFile, urlFilePath,"a+") <0)
		{
			fopen_s(&m_urlFile,urlFilePath,"w+");
		}
		if(m_urlFile != 0x00000000)
		{
			//写日志文件
			fputs( DateTimeNow() + "GET-DATA-SUCCESS SENDING... METHOD:" + ma_method 
				+ " HOST:" + ma_host 
				+  " URL:" + ma_url 
				+ " Cookie:" + ma_cookie 
				+ " POSTDATA:" + ma_postData 
				+ "\r\n", m_urlFile);
			fclose(m_urlFile);
		}

	}
	catch(...)
	{

	}

	SendMessage(hSendBackHwnd,WM_QZJWINPCAP,QW_REGROUPED,(LPARAM)ma_url);
}

//*******************************************************************************************************
//SetFilter: 
//					Set one filter.
//
//*******************************************************************************************************
int CQzjWinpcap::SetFilter(char* name, char* url, char* host, bool isPost)
{

	int i = 0;
	while(i <MAXQUEUE && FilterHosts[i][0] != '\0')
		i++;
	if (i>=MAXQUEUE)
		return -1;
	if (strlen(host)> HOST_LENGTH_LIMIATION || 
		strlen(url) > URL_LENGTH_LIMIATION ||
		strlen(name) > URL_LENGTH_LIMIATION
		)
		return -2;
	strcpy_s(FilterHosts[i],host);
	strcpy_s(FilterUrl[i],url);
	strcpy_s(FilterName[i], name);
	FilterMethodPost[i] = isPost;
	fputs("\r\n" ,pfilter);
	fputs(" INFO: Name ==> ",pfilter);
	fputs(name,pfilter);
	fputs("\r\n INFO: Host ==> ",pfilter);
	fputs(host,pfilter);
	fputs("\r\n INFO: Url ==> ",pfilter);
	fputs(url,pfilter);
	fputs("\r\n INFO: Is Post ==> " ,pfilter);
	fputs(isPost?"Yes":"No",pfilter);
	fputs("\r\n" ,pfilter);
	fflush(pfilter);
	return 0;  
}

//*******************************************************************************************************
//RemoveAllFilters: 
//					Remove all filters.
//
//*******************************************************************************************************
int CQzjWinpcap::RemoveAllFilters()
{
	int i = 0;
	while(i <MAXQUEUE)
	{
		FilterHosts[i][0] = '\0';
		FilterUrl[i][0] = '\0';
		i++;
	}
	return 0;
}

//*******************************************************************************************************
//SetFilter: 
//					Set more than one filter at one time.
//
//*******************************************************************************************************
int CQzjWinpcap::SetFilters(char* filters)
{


	if ( fopen_s(&pfilter,m_packetRecordFilepath + "Filters_" + m_packetRecordFilename,"a+") <0)
	{
		if ( fopen_s(&pfilter,m_packetRecordFilepath + "Filters_" + m_packetRecordFilename,"w+") <0)
			return -2;
	}
	else
	{
		fputs("\r\n==========Filters============\r\n",pfilter);
		fputs(">>>>>>>>QZJWINPCAP Filters Data<<<<<<<<<\r\n",pfilter);
		fputs(DateTimeNow(),pfilter);
		fputs(" INFO: \r\n",pfilter);
		fputs(filters,pfilter);
		fflush(pfilter);
	}
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
	char *b, *e, *p;
	char *host, *url, *post, *name;
	int count = 0;
	long filtersLen = strlen(filters);
	b = filters;
	do
	{
		if (NULL == (b = strstr(b,"[Filter]")))
			break;
		if (NULL == (e = strstr(b,"[/Filter]")))
			break;
		*e = '\0';
		/////////////
		if (NULL == (name = strstr(b, "[Name]"))
			||
			NULL == (host = strstr(b, "[Host]"))
			||
			NULL == (url = strstr(b, "[Url]"))
			||
			NULL == (post = strstr(b, "[Post]"))
			)
			break;
		/////////////
		name += 6;
		host += 6;
		url += 5;
		post += 6;
		(*strstr(name, "[/Name]")) = '\0';
		(*strstr(host, "[/Host]")) = '\0';
		(*strstr(url, "[/Url]")) = '\0';
		(*strstr(post, "[/Post]")) = '\0';
		SetFilter(name, url, host, (strcmp(post,"True")==0?true:false));
		fputs(" INFO: One filter set completed.\r\n",pfilter);
		fflush(pfilter);
		count++;
		if (e - filters >= filtersLen 
			- 8)
			break;
		b = e+1;
	}while(true);
	fclose(pfilter);
	return count;
}


int CQzjWinpcap::SetPacketRecordFilePath(char *filepath)
{
	m_packetRecordFilepath.Format("%s", filepath);
	if (m_packetRecordFilepath.Right(1) != "\\")
		m_packetRecordFilepath += "\\";
	m_packetRecordFilepath += "MatchingClientLog\\";

	//创建系统日志文件夹
	if(GetFileAttributes(m_packetRecordFilepath) == 0xFFFFFFFF)
	{
		CreateDirectory(m_packetRecordFilepath,NULL);
	}
	return 0;
}

CString  CQzjWinpcap::GetRecordFilepath()
{
	return m_packetRecordFilepath;
}
