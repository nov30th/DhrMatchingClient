/*****************************************************
Copyright 1985-2010 QZJ
Socket IP TCP HTTP
Post data to web server
Created At:2010.9.17
By Vincent.Qiu
nov30th@gmail.com
******************************************************/

#pragma once


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>


#define MEM_BUFFER_SIZE 10

/* 
HTTPRequest: Structure that returns the HTTP headers and message
from the request
*/
typedef struct
{ 
    LPSTR headerSend;								// Pointer to HTTP header Send 
    LPSTR headerReceive;					// Pointer to HTTP headers Receive
    LPSTR message;									  // Pointer to the HTTP message 
    long messageLength;					 // Length of the message 
} HTTPRequest;

/* 
MemBuffer:	Structure used to implement a memory buffer, which is a
buffer of memory that will grow to hold variable sized
parts of the HTTP message. 
*/
typedef struct
{
    unsigned	char *buffer;
    unsigned	char *position;
    size_t		size;
} MemBuffer;


class CQzjHttpPost  
{
public:
    CQzjHttpPost();
    virtual ~CQzjHttpPost();

private:
    void		MemBufferCreate(MemBuffer *b);
    void		MemBufferGrow(MemBuffer *b);
    void		MemBufferAddByte(MemBuffer *b, unsigned char byt);
    void		MemBufferAddBuffer(MemBuffer *b, unsigned char *buffer, size_t size);
    DWORD		GetHostAddress(LPCSTR host);
    void		SendString(SOCKET sock,LPCSTR str);
    BOOL		ValidHostChar(char ch);
    void		ParseURL(LPCSTR url,LPSTR protocol,int lprotocol, LPSTR host,int lhost,LPSTR request,int lrequest,int *port);

    int			SendHTTP(LPCSTR url,LPCSTR headers,BYTE *post, DWORD postLength,HTTPRequest *req);

public:
    //void		SendRequest(bool IsPost, LPCSTR url, char *pszHeaderSend, char *pszHeaderReceive, char *pszMessage);
    int		SendRequest(bool IsPost, LPCSTR url, CString &psHeaderSend, CString &psHeaderReceive, CString &psMessage);
};
