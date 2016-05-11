#pragma once

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

class BaseSocket
{
public:
    BaseSocket();
    virtual ~BaseSocket();
    virtual void Close() = 0;
    virtual void BindErrorFunction(function<void(BaseSocket*)> fError);
    virtual void BindCloseFunction(function<void(BaseSocket*)> fCloseing);

protected:
    typedef tuple<SOCKET, string, short, string, short> SOCKINFO;
    virtual void SetSocketOption(SOCKET& fd);
    virtual void OnError();

protected:
    SOCKET m_fSock;
    thread m_thListen;
    bool   m_bStop;
    bool   m_bAutoDelClass;
    int    m_iError;
    int    m_iShutDownState;
    function<void(BaseSocket*)> m_fError;
    function<void(BaseSocket*)> m_fCloseing;

private:
    static atomic_uint s_atRefCount;
};

class TcpSocket : public BaseSocket
{
protected:
    typedef tuple<shared_ptr<uint8_t>, size_t> DATA;

public:
    TcpSocket();
    virtual ~TcpSocket();
    virtual bool Connect(const char* const szIpToWhere, short sPort);
    virtual uint32_t Read(void* buf, uint32_t len);
    virtual uint32_t Write(const void* buf, uint32_t len);
    void StartReceiving();
    virtual void Close();
    virtual uint32_t GetBytesAvailible();
    virtual uint32_t GetOutBytesInQue();
    virtual void BindFuncBytesRecived(function<void(TcpSocket*)> fBytesRecived);
    virtual void BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted);
    virtual bool IsSslConnection() { return false; }

    string GetClientAddr() { return m_strClientAddr; }
    short GetClientPort() { return m_sClientPort; }
    string GetInterfaceAddr() { return m_strClientAddr; }
    short GetInterfacePort() { return m_sIFacePort; }

protected:
    friend TcpServer;
    TcpSocket(SOCKINFO SockInfo);

private:
    void SelectThread();
    void ConnectThread();
    void AutoDelete();

private:
    mutex            m_mxInDeque;
    deque<DATA>      m_quInData;
    atomic<uint32_t> m_atInBytes;
    mutex            m_mxOutDeque;
    deque<DATA>      m_quOutData;
    atomic<uint32_t> m_atOutBytes;
    atomic<bool>     m_atWriteThread;

    mutex            m_mtAutoDelete;
    bool             m_bAutoDelete;

    string           m_strClientAddr;
    short            m_sClientPort;
    string           m_strIFaceAddr;
    short            m_sIFacePort;

    function<void(TcpSocket*)> m_fBytesRecived;
    function<void(TcpSocket*)> m_fClientConneted;
};

class TcpServer : public BaseSocket
{
public:
    virtual ~TcpServer();
    bool Start(const char* szIpAddr, short sPort);
    size_t GetPendigConnectionCount();
    virtual TcpSocket* GetNextPendingConnection();
    void BindNewConnection(function<void(TcpServer*, int)> fNewConnetion);
    virtual void Close();

private:
    void Delete();
    void SelectThread();

protected:
    vector<SOCKINFO> m_vSockAccept;
    mutex            m_mtAcceptList;

private:
    vector<SOCKET> m_vSock;
    function<void(TcpServer*, int)> m_fNewConnection;
};

class UdpSocket : public BaseSocket
{
    typedef tuple<shared_ptr<uint8_t>, size_t, string> DATA;

public:
    UdpSocket();
    virtual ~UdpSocket();
    bool Create(const char* const szIpToWhere, short sPort);
    bool AddToMulticastGroup(const char* const szMulticastIp);
    bool RemoveFromMulticastGroup(const char* const szMulticastIp);
    uint32_t Read(void* buf, uint32_t len, string& strFrom);
    uint32_t Write(const void* buf, uint32_t len, const string& strTo);
    void Close();
    uint32_t GetBytesAvailible();
    void BindFuncBytesRecived(function<void(UdpSocket*)> fBytesRecived);

private:
    void SelectThread();

private:
    mutex            m_mxInDeque;
    deque<DATA>      m_quInData;
    atomic<uint32_t> m_atInBytes;
    mutex            m_mxOutDeque;
    deque<DATA>      m_quOutData;
    atomic<uint32_t> m_atOutBytes;
    atomic<bool>     m_atWriteThread;

    mutex            m_mtAutoDelete;
    bool             m_bAutoDelete;

    function<void(UdpSocket*)> m_fBytesRecived;
};
