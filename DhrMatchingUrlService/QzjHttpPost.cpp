/*****************************************************
Copyright 1985-2010 QZJ
Socket IP TCP HTTP
Post data to web server
Created At:2010.9.17
By Vincent.Qiu
nov30th@gmail.com
******************************************************/

#include "stdafx.h"

#include "QzjHttpPost.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CQzjHttpPost::CQzjHttpPost()
{

}

CQzjHttpPost::~CQzjHttpPost()
{

}


//*******************************************************************************************************
//MemBufferCreate: 
//					Passed a MemBuffer structure, will allocate a memory buffer 
//                   of MEM_BUFFER_SIZE.  This buffer can then grow as needed.
//*******************************************************************************************************
void CQzjHttpPost::MemBufferCreate(MemBuffer *b)
{
    b->size = MEM_BUFFER_SIZE;
    b->buffer =(unsigned	char *) malloc( b->size );
    b->position = b->buffer;
}

//*******************************************************************************************************
// MemBufferGrow:  
//					Double the size of the buffer that was passed to this function. 
//*******************************************************************************************************
void CQzjHttpPost::MemBufferGrow(MemBuffer *b)
{
    size_t sz;
    sz = b->position - b->buffer;
    b->size = b->size *2;
    b->buffer =(unsigned	char *) realloc(b->buffer,b->size);
    b->position = b->buffer + sz;	// readjust current position
}

//*******************************************************************************************************
// MemBufferAddByte: 
//					Add a single byte to the memory buffer, grow if needed.
//*******************************************************************************************************
void CQzjHttpPost::MemBufferAddByte(MemBuffer *b,unsigned char byt)
{
    if( (size_t)(b->position-b->buffer) >= b->size )
        MemBufferGrow(b);

    *(b->position++) = byt;
}

//*******************************************************************************************************
// MemBufferAddBuffer:
//					Add a range of bytes to the memory buffer, grow if needed.
//*******************************************************************************************************
void CQzjHttpPost::MemBufferAddBuffer(MemBuffer *b,
    unsigned char *buffer, size_t size)
{
    while( ((size_t)(b->position-b->buffer)+size) >= b->size )
        MemBufferGrow(b);

    memcpy(b->position,buffer,size);
    b->position+=size;
}

//*******************************************************************************************************
// GetHostAddress: 
//					Resolve using DNS or similar(WINS,etc) the IP 
//                   address for a domain name such as www.wdj.com. 
//*******************************************************************************************************
DWORD CQzjHttpPost::GetHostAddress(LPCSTR host)
{
    struct hostent *phe;
    char *p;

    phe = gethostbyname( host );

    if(phe==NULL)
        return 0;

    p = *phe->h_addr_list;
    return *((DWORD*)p);
}

//*******************************************************************************************************
// SendString: 
//					Send a string(null terminated) over the specified socket.
//*******************************************************************************************************
void CQzjHttpPost::SendString(SOCKET sock,LPCSTR str)
{
    send(sock,str,strlen(str),0);
}

//*******************************************************************************************************
// ValidHostChar: 
//					Return TRUE if the specified character is valid
//						for a host name, i.e. A-Z or 0-9 or -.: 
//*******************************************************************************************************
BOOL CQzjHttpPost::ValidHostChar(char ch)
{
    return( isalpha(ch) || isdigit(ch)
        || ch=='-' || ch=='.' || ch==':' );
}


//*******************************************************************************************************
// ParseURL: 
//					Used to break apart a URL such as 
//						http://www.localhost.com:80/TestPost.htm into protocol, port, host and request.
//*******************************************************************************************************
void CQzjHttpPost::ParseURL(LPCSTR url, LPSTR protocol, int lprotocol, 
    LPSTR host, int lhost, LPSTR request, int lrequest, int *port)
{
    char *work,*ptr,*ptr2;

    *protocol = *host = *request = 0;
    *port = 80;

    work = strdup(url);
    strupr(work);

    ptr = strchr(work,':');							// find protocol if any
    if(ptr != NULL)
    {
        *(ptr++) = 0;
        lstrcpyn(protocol,work,lprotocol);
    }
    else
    {
        lstrcpyn(protocol,"HTTP",lprotocol);
        ptr = work;
    }

    if( (*ptr=='/') && (*(ptr+1)=='/') )			// skip past opening /'s 
        ptr+=2;

    ptr2 = ptr;										// find host
    while( ValidHostChar(*ptr2) && *ptr2 )
        ptr2++;
    *ptr2 = 0;

    //获取IP地址
    lstrcpyn(host, ptr, lhost);
    //获取请求内容
    lstrcpyn(request, url + (ptr2 - work), lrequest);

    //获取端口号
    ptr = strchr(host, ':');
    if(ptr != NULL)
    {
        *ptr = 0;
        *port = atoi(ptr + 1);
    }

    free(work);
}

//*******************************************************************************************************
// SendHTTP: 
//					Main entry point for this code.  
//					  url			- The URL to GET/POST to/from.
//					  headerSend		- Headers to be sent to the server.
//					  post			- Data to be posted to the server, NULL if GET.
//					  postLength	- Length of data to post.
//					  req			- Contains the message and headerSend sent by the server.
//
//					  returns 1 on failure, 0 on success.
//*******************************************************************************************************
int CQzjHttpPost::SendHTTP(LPCSTR url, LPCSTR headerReceive, BYTE *post, DWORD postLength, HTTPRequest *req)
{
    WSADATA			WsaData;
    SOCKADDR_IN		sin;
    SOCKET			sock;
    char			buffer[512];
    char			protocol[20], host[256], request[20000];
    int				l, port, chars, err;
    MemBuffer		headersBuffer, messageBuffer;
    char			headerSend[30000];
    BOOL			done;

    // 格式化 URL
    ParseURL(url, protocol, sizeof(protocol), host, sizeof(host), request, sizeof(request), &port);

    if(strcmp(protocol, "HTTP"))
        return 1;

    err = WSAStartup(0x0101, &WsaData); 
    //初始化失败
    if(err != 0)
        return 1;

    sock = socket (AF_INET, SOCK_STREAM, 0);
    //创建socket失败
    if (sock == INVALID_SOCKET)
        return 1;

    sin.sin_family = AF_INET;		//地址类型为internetwork  
    sin.sin_addr.s_addr = GetHostAddress(host);  //设置广播地址
    sin.sin_port = htons( (unsigned short)port );  //设置端口号

    //测试连接
    if(connect(sock, (LPSOCKADDR)&sin, sizeof(SOCKADDR_IN) ))
    {
        return 1;
    }

    if( !*request )
        lstrcpyn(request, "/", sizeof(request));

    if( post == NULL )
    {
        SendString(sock,"GET ");
        strcpy(headerSend, "GET ");
    }
    else 
    {
        SendString(sock,"POST ");
        strcpy(headerSend, "POST ");
    }
    SendString(sock,request);
    strcat(headerSend, request);

    SendString(sock," HTTP/1.0\r\n");
    strcat(headerSend, " HTTP/1.0\r\n");

    SendString(sock,"Accept: image/gif, image/x-xbitmap,"
        " image/jpeg, image/pjpeg, application/vnd.ms-excel,"
        " application/msword, application/vnd.ms-powerpoint,"
        " */*\r\n");
    strcat(headerSend, "Accept: image/gif, image/x-xbitmap,"
        " image/jpeg, image/pjpeg, application/vnd.ms-excel,"
        " application/msword, application/vnd.ms-powerpoint,"
        " */*\r\n");

    SendString(sock,"Accept-Language: en-us\r\n");
    strcat(headerSend, "Accept-Language: en-us\r\n");

    SendString(sock,"User-Agent: Mozilla/4.0\r\n");
    strcat(headerSend, "User-Agent: Mozilla/4.0\r\n");

    if(postLength)
    {
        wsprintf(buffer,"Content-Length: %ld\r\n",postLength);
        SendString(sock,buffer);
        strcat(headerSend, buffer);
    }

    SendString(sock,"Host: ");
    strcat(headerSend, "Host: ");

    SendString(sock,host);
    strcat(headerSend, host);

    SendString(sock,"\r\n");
    strcat(headerSend, "\r\n");

    if( (headerReceive!=NULL) && *headerReceive )
    {
        SendString(sock,headerReceive);
        strcat(headerSend, headerReceive);
    }

    SendString(sock,"\r\n");								// Send a blank line to signal end of HTTP headerReceive
    strcat(headerSend, "\r\n");

    if( (post!=NULL) && postLength )
    {
        send(sock,(const char*)post,postLength,0);
        post[postLength]	= '\0';

        strcat(headerSend, (const char*)post);
    }

    //strcpy(req->headerSend, headerSend);
    req->headerSend		= (char*) malloc( sizeof(char*) * strlen(headerSend));
    strcpy(req->headerSend, (char*) headerSend );

    MemBufferCreate(&headersBuffer );
    chars = 0;
    done = FALSE;

    while(!done)
    {
        l = recv(sock, buffer, 1, 0);
        if(l < 0)
            done = TRUE;

        switch(*buffer)
        {
        case '\r':
            break;
        case '\n':
            if(chars == 0)
                done = TRUE;
            chars = 0;
            break;
        default:
            chars++;
            break;
        }

        MemBufferAddByte(&headersBuffer,*buffer);
    }

    req->headerReceive	= (char*) headersBuffer.buffer;
    *(headersBuffer.position) = 0;

    MemBufferCreate(&messageBuffer);							
    // 读取 HTTP body
    do
    {
        l = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if(l < 0)
            break;
        *(buffer + l) = 0;
        MemBufferAddBuffer(&messageBuffer, (unsigned char*)&buffer, l);
    } while(l > 0);
    *messageBuffer.position = 0;
    req->message = (char*) messageBuffer.buffer;
    req->messageLength = (messageBuffer.position - messageBuffer.buffer);

    closesocket(sock);											// Cleanup

    return 0;
}


//*******************************************************************************************************
// SendRequest
//
//*******************************************************************************************************
//void CQzjHttpPost::SendRequest(bool IsPost, LPCSTR url, char *pszHeaderSend, char *pszHeaderReceive, char *pszMessage)
int CQzjHttpPost::SendRequest(bool IsPost, LPCSTR url, CString &psHeaderSend, CString &psHeaderReceive, CString &psMessage)
{
    HTTPRequest			req;
    int					i,j,rtn;
    FILE				*fp;
    LPSTR				buffer;

    req.headerSend							= NULL;
    req.headerReceive						= NULL;
    req.message								= NULL;

    //Read in arguments


    if(IsPost)
    {			
        //设置缓存区大小
        i	= psHeaderSend.GetLength();
        buffer  = (char*) malloc(i + 1);
        strcpy(buffer, (LPCTSTR)psHeaderSend);

        rtn	= SendHTTP(	url,
            "Content-Type: application/x-www-form-urlencoded\r\n",
            (unsigned char*)buffer,
            i,
            &req);

        free(buffer);
    }
    else												/* GET */
        rtn = SendHTTP(url,NULL,NULL,0,&req);


    if(!rtn)											//Output message and/or headerSend 
    {
        psHeaderSend		= req.headerSend;
        psHeaderReceive		= req.headerReceive;
        psMessage			= req.message;


        free(req.headerSend);
        free(req.headerReceive);
        free(req.message);
    }
    else
    {
        //printf("\nFailed\n");
        return -1;
        //MessageBox(0, "Retrieve Failed", "", 0);
    }

    return rtn;
}

