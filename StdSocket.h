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
    virtual void SetSocketOption(const SOCKET& fd);
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
#pragma message("TODO!!! Folge Zeile wieder entfernen.")
    friend int main(int, const char*[]);
    static atomic_uint s_atRefCount;
};

class TcpSocket : public BaseSocket
{
protected:
    typedef tuple<shared_ptr<uint8_t>, size_t> DATA;

public:
    TcpSocket();
    virtual ~TcpSocket();
    virtual bool Connect(const char* const szIpToWhere, const short sPort);
    virtual uint32_t Read(void* buf, uint32_t len);
    virtual uint32_t Write(const void* buf, uint32_t len);
    void StartReceiving();
    virtual void Close();
    virtual uint32_t GetBytesAvailible() const;
    virtual uint32_t GetOutBytesInQue() const;
    virtual void BindFuncBytesRecived(function<void(TcpSocket*)> fBytesRecived);
    virtual void BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted);
    virtual bool IsSslConnection() const { return false; }

    const string& GetClientAddr() const { return m_strClientAddr; }
    short GetClientPort() const { return m_sClientPort; }
    const string& GetInterfaceAddr() const { return m_strClientAddr; }
    short GetInterfacePort() const { return m_sIFacePort; }

protected:
    friend TcpServer;
    TcpSocket(const SOCKET);

private:
    void SelectThread();
    void ConnectThread();
    void GetConnectionInfo();

private:
    mutex            m_mxInDeque;
    deque<DATA>      m_quInData;
    atomic<uint32_t> m_atInBytes;
    mutex            m_mxOutDeque;
    deque<DATA>      m_quOutData;
    atomic<uint32_t> m_atOutBytes;
    atomic<bool>     m_atWriteThread;
    atomic<bool>     m_atDeleteThread;

    mutex            m_mtAutoDelete;
    bool             m_bAutoDelete;
    bool             m_bCloseReq;

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
    bool Start(const char* const szIpAddr, const short sPort);
    size_t GetPendigConnectionCount();
    virtual TcpSocket* const GetNextPendingConnection();
    void BindNewConnection(function<void(TcpServer*, int)> fNewConnetion);
    virtual void Close();

private:
    void Delete();
    void SelectThread();

protected:
    vector<SOCKET> m_vSockAccept;
    mutex          m_mtAcceptList;

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
    bool Create(const char* const szIpToWhere, const short sPort);
    bool AddToMulticastGroup(const char* const szMulticastIp);
    bool RemoveFromMulticastGroup(const char* const szMulticastIp);
    uint32_t Read(void* buf, uint32_t len, string& strFrom);
    uint32_t Write(const void* buf, uint32_t len, const string& strTo);
    void Close();
    uint32_t GetBytesAvailible() const;
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
