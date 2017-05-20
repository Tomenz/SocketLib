/* Copyright (C) Hauck Software Solutions - All Rights Reserved
* You may use, distribute and modify this code under the terms
* that changes to the code must be reported back the original
* author
*
* Company: Hauck Software Solutions
* Author:  Thomas Hauck
* Email:   Thomas@fam-hauck.de
*
*/
#pragma once
#ifndef STDSOCKET
#define STDSOCKET

#include <thread>
#include <future>
#include <deque>

#if defined (_WIN32) || defined (_WIN64)
// https://support.microsoft.com/de-de/kb/257460
//#include <winsock2.h>
#include <Ws2tcpip.h>
#else
#define SOCKET int32_t
#endif

#define BUFFER(x) get<0>(x)
#define BUFLEN(x) get<1>(x)
#define ADDRESS(x) get<2>(x)

using namespace std;

class TcpServer;

class InitSocket
{
public:
    static InitSocket* GetInstance();
    ~InitSocket();

private:
    InitSocket();
};

class BaseSocket
{
public:
    BaseSocket();
    virtual ~BaseSocket();
    virtual void Close() = 0;
    virtual void BindErrorFunction(function<void(BaseSocket*)> fError);
    virtual void BindCloseFunction(function<void(BaseSocket*)> fCloseing);
    virtual int GetErrorNo() const { return m_iError; }
    virtual void SetErrorNo(int iErrNo) { m_iError = iErrNo; }
    virtual uint16_t GetSocketPort();
    static int EnumIpAddresses(function<int(int,const string&,int,void*)> fnCallBack, void* vpUser);

protected:
    virtual void SetSocketOption(const SOCKET& fd);
    virtual void OnError();

protected:
    SOCKET m_fSock;
    thread m_thListen;
    thread m_thWrite;
    bool   m_bStop;
    int    m_iError;
    atomic_uchar                m_iShutDownState;
    function<void(BaseSocket*)> m_fError;
    function<void(BaseSocket*)> m_fCloseing;

private:
#pragma message("TODO!!! Folge Zeile wieder entfernen.")
    friend int main(int, const char*[]);
    friend void sigusr1_handler(int);
    static atomic_uint s_atRefCount;
};

class TcpSocket : public BaseSocket
{
protected:
    typedef tuple<shared_ptr<uint8_t>, uint32_t> DATA;

public:
    TcpSocket();
    virtual ~TcpSocket();
    virtual bool Connect(const char* const szIpToWhere, const uint16_t sPort);
    virtual uint32_t Read(void* buf, uint32_t len);
    virtual size_t Write(const void* buf, size_t len);
    void StartReceiving();
    virtual void Close();
    virtual uint32_t GetBytesAvailible() const;
    virtual uint32_t GetOutBytesInQue() const;
    virtual void BindFuncBytesRecived(function<void(TcpSocket*)> fBytesRecived);
    virtual void BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted);
    virtual bool IsSslConnection() const { return false; }

    const string& GetClientAddr() const { return m_strClientAddr; }
    uint16_t GetClientPort() const { return m_sClientPort; }
    const string& GetInterfaceAddr() const { return m_strClientAddr; }
    uint16_t GetInterfacePort() const { return m_sIFacePort; }

    const TcpServer* GetServerSocketRef() const { return m_pRefServSocket; }

protected:
    friend TcpServer;
    explicit TcpSocket(const SOCKET, const TcpServer* pRefServSocket);
    virtual void SetSocketOption(const SOCKET& fd);

private:
    void WriteThread();
    void SelectThread();
    void ConnectThread();
    bool GetConnectionInfo();

private:
    mutex            m_mxInDeque;
    deque<DATA>      m_quInData;
    atomic<uint32_t> m_atInBytes;
    mutex            m_mxOutDeque;
    deque<DATA>      m_quOutData;
    atomic<uint32_t> m_atOutBytes;

    bool             m_bCloseReq;
    condition_variable m_cv;

    string           m_strClientAddr;
    uint16_t         m_sClientPort;
    string           m_strIFaceAddr;
    uint16_t         m_sIFacePort;

    const TcpServer* m_pRefServSocket;

    function<void(TcpSocket*)> m_fBytesRecived;
    function<void(TcpSocket*)> m_fClientConneted;

#pragma message("TODO!!! Folge Zeile wieder entfernen.")
    friend void sigusr1_handler(int);
    friend int main(int, const char*[]);
};

class TcpServer : public BaseSocket
{
public:
    virtual ~TcpServer();
    bool Start(const char* const szIpAddr, const short sPort);
    unsigned short GetServerPort();
    void BindNewConnection(function<void(const vector<TcpSocket*>&)>);
    virtual void Close();
    virtual TcpSocket* const MakeClientConnection(const SOCKET&);

protected:
    virtual void SetSocketOption(const SOCKET& fd);

private:
    void Delete();
    void SelectThread();

protected:
    vector<SOCKET> m_vSockAccept;
    mutex          m_mtAcceptList;

private:
    vector<SOCKET> m_vSock;
    function<void(const vector<TcpSocket*>&)> m_fNewConnection;
};

class UdpSocket : public BaseSocket
{
protected:
    typedef tuple<shared_ptr<uint8_t>, uint32_t, string> DATA;

public:
    UdpSocket();
    virtual ~UdpSocket();
    virtual bool Create(const char* const szIpToWhere, const short sPort, const char* const szIpToBind = nullptr);
    virtual bool AddToMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex);
    virtual bool RemoveFromMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex);
    virtual uint32_t Read(void* buf, uint32_t len, string& strFrom);
    virtual size_t Write(const void* buf, size_t len, const string& strTo);
    virtual void Close();
    virtual uint32_t GetBytesAvailible() const;
    virtual uint32_t GetOutBytesInQue() const;
    virtual void BindFuncBytesRecived(function<void(UdpSocket*)> fBytesRecived);

private:
    void WriteThread();
    void SelectThread();

private:
    mutex            m_mxInDeque;
    deque<DATA>      m_quInData;
    atomic<uint32_t> m_atInBytes;
    mutex            m_mxOutDeque;
    deque<DATA>      m_quOutData;
    atomic<uint32_t> m_atOutBytes;

    bool             m_bCloseReq;
    condition_variable m_cv;

    function<void(UdpSocket*)> m_fBytesRecived;
};

#endif
