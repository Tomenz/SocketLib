/* Copyright (C) 2016-2020 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
*/

#ifndef STDSOCKET_H
#define STDSOCKET_H

#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <functional>
#include <thread>
#include <condition_variable>

#if defined (_WIN32) || defined (_WIN64)
// https://support.microsoft.com/de-de/kb/257460
#include <Ws2tcpip.h>
#include <Netioapi.h>
#else
#include <sys/socket.h>
#define SOCKET int32_t
#endif

#define BUFFER(x) get<0>(x)
#define BUFLEN(x) get<1>(x)
#define ADDRESS(x) get<2>(x)

using namespace std;

#include "SocketLib.h"

class InitSocket
{
public:
    static InitSocket& GetInstance() noexcept;
    ~InitSocket();
    InitSocket(const InitSocket&) = delete;
    InitSocket(InitSocket&&) = delete;
    InitSocket& operator=(const InitSocket&) = delete;
    InitSocket& operator=(InitSocket&&) = delete;
    void SetAddrNotifyCallback(const function<void(bool, const string&, int, int)>& fnCbAddrNotify);

private:
    InitSocket() noexcept;
#if defined (_WIN32) || defined (_WIN64)
    static VOID __stdcall IpIfaceChanged(PVOID CallerContext, PMIB_IPINTERFACE_ROW Row, MIB_NOTIFICATION_TYPE NotificationType);
    HANDLE m_hIFaceNotify;
#else
    void IpChangeThread();
    thread m_thIpChange;
    bool   m_bStopThread;
#endif
    int CbEnumIpAdressen(int iFamily, const string& strIp, int nInterFaceId, void* vpUserParam);
    void NotifyOnAddressChanges(vector<tuple<string, int, int>>& vNewListing);

    vector<tuple<string, int, int>> m_vCurIPAddr;
    mutex m_mxCurIpAddr;
    function<void(bool, const string&, int, int)> m_fnCbAddrNotify;
};

class BaseSocketImpl
{
public:
    explicit BaseSocketImpl() noexcept;
    virtual ~BaseSocketImpl();
    BaseSocketImpl(const BaseSocketImpl&) = delete;
    BaseSocketImpl(BaseSocketImpl&&) = delete;
    BaseSocketImpl& operator=(const BaseSocketImpl&) = delete;
    BaseSocketImpl& operator=(BaseSocketImpl&&) = delete;

    virtual void Close() = 0;
    virtual function<void(BaseSocket*)> BindErrorFunction(function<void(BaseSocket*)> fError) noexcept;
    virtual function<void(BaseSocket*, void*)> BindErrorFunction(function<void(BaseSocket*, void*)> fError) noexcept;
    virtual function<void(BaseSocket*)> BindCloseFunction(function<void(BaseSocket*)> fClosing) noexcept;
    virtual function<void(BaseSocket*, void*)> BindCloseFunction(function<void(BaseSocket*, void*)> fClosing) noexcept;
    virtual void SetCallbackUserData(void*) noexcept;
    virtual int GetErrorNo() const  noexcept { return m_iError; }
    virtual int GetErrorLoc() const  noexcept { return m_iErrLoc; }
    virtual void SetErrorNo(int iErrNo) noexcept { m_iError = iErrNo; }
    virtual uint16_t GetSocketPort();
    static int EnumIpAddresses(function<int(int,const string&,int,void*)> fnCallBack, void* vpUser);
    static void SetAddrNotifyCallback(const function<void(bool, const string&, int, int)>& fnCbAddrNotify);
    virtual void SetSocketName(const string& strName) { m_strName = strName; }
    virtual string& GetSocketName() noexcept { return m_strName; }

    static void SetTrafficDebugCallback(function<void(const uint16_t, const char*, size_t, bool)> fnCbTrafficDbg) { s_fTrafficDebug = fnCbTrafficDbg; }
    static size_t GetNrOfClientSockets() { lock_guard<mutex> lock(s_mxClientSocket); return s_lstClientSocket.size(); }

protected:
    explicit BaseSocketImpl(BaseSocketImpl* pBaseSocket);
    virtual void SetSocketOption(const SOCKET& fd);
    virtual void OnError();
    virtual void StartClosingCB();

protected:
    SOCKET                      m_fSock;
    string                      m_strName;
    thread                      m_thListen;
    thread                      m_thWrite;
    mutex                       m_mxWrite;
    thread                      m_thClose;
    bool                        m_bStop;
    int                         m_iError;
    int                         m_iErrLoc;
    atomic_uchar                m_iShutDownState;
    function<void(BaseSocket*)> m_fError;
    function<void(BaseSocket*, void*)> m_fErrorParam;
    function<void(BaseSocket*)> m_fClosing;
    function<void(BaseSocket*, void*)> m_fClosingParam;
    void*                       m_pvUserData;
    mutex                       m_mxFnClosing;
    BaseSocket*                 m_pBkRef;
    static deque<unique_ptr<BaseSocket>> s_lstClientSocket;
    static mutex                s_mxClientSocket;
    static function<void(const uint16_t, const char*, size_t, bool)> s_fTrafficDebug;
};

class TcpSocketImpl : public BaseSocketImpl
{
protected:
    typedef tuple<unique_ptr<uint8_t[]>, size_t> DATA;

public:
    TcpSocketImpl(BaseSocket* pBkRef);
    ~TcpSocketImpl();
    TcpSocketImpl(const TcpSocketImpl&) = delete;
    TcpSocketImpl(TcpSocketImpl&&) = delete;
    TcpSocketImpl& operator=(const TcpSocketImpl&) = delete;
    TcpSocketImpl& operator=(TcpSocketImpl&&) = delete;

    virtual bool Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint = AF_UNSPEC);
    virtual size_t Read(void* buf, size_t len);
    virtual size_t PutBackRead(void* buf, size_t len);
    virtual size_t Write(const void* buf, size_t len);
    void StartReceiving();
    void Close() override;
    virtual void SelfDestroy();
    virtual void Delete();
    virtual size_t GetBytesAvailable() const noexcept;
    virtual size_t GetOutBytesInQue() const noexcept;
    virtual function<void(TcpSocket*)> BindFuncBytesReceived(function<void(TcpSocket*)> fBytesReceived) noexcept;
    virtual function<void(TcpSocket*, void*)> BindFuncBytesReceived(function<void(TcpSocket*, void*)> fBytesReceived) noexcept;
    virtual function<void(TcpSocket*)> BindFuncConEstablished(function<void(TcpSocket*)> fClientConnected) noexcept;
    virtual function<void(TcpSocket*, void*)> BindFuncConEstablished(function<void(TcpSocket*, void*)> fClientConnected) noexcept;
    virtual bool IsSslConnection() const noexcept { return false; }

    const string& GetClientAddr() const noexcept { return m_strClientAddr; }
    uint16_t GetClientPort() const noexcept { return m_sClientPort; }
    const string& GetInterfaceAddr() const noexcept { return m_strIFaceAddr; }
    uint16_t GetInterfacePort() const noexcept { return m_sIFacePort; }

    const TcpServer* GetServerSocketRef() const noexcept { return m_pRefServSocket; }

protected:
    friend class TcpServerImpl;       // The Server class needs access to the private constructor in the next line
    friend class SslTcpServerImpl;    // The Server class needs access to the private constructor in the next line
    explicit TcpSocketImpl(BaseSocket* pBkRef, TcpSocketImpl* pTcpSocketImpl);
    void SetSocketOption(const SOCKET& fd) override;
    void TriggerWriteThread();
    virtual void BindFuncConEstablished(function<void(TcpSocketImpl*)> fClientConnected) noexcept;
    bool GetConnectionInfo();

    void WriteThread();

private:
    void SelectThread();
    void ConnectThread();

protected:
    function<int()>  m_fnSslInitDone;
    deque<DATA>      m_quTmpOutData;
    function<int(const uint8_t*, size_t, bool&)> m_fnSslDecode;
    mutex            m_mxInDeque;
    deque<DATA>      m_quInData;
    atomic<size_t>   m_atInBytes;

    function<int(const uint8_t*, size_t)> m_fnSslEncode;
    mutex            m_mxOutDeque;
    deque<DATA>      m_quOutData;
    atomic<size_t>   m_atOutBytes;

    function<void(TcpSocket*)> m_fClientConnected;
    function<void(TcpSocket*, void*)> m_fClientConnectedParam;

    const TcpServer* m_pRefServSocket;

private:
    thread           m_thConnect;

    bool             m_bCloseReq;
    condition_variable m_cv;

    string           m_strClientAddr;
    uint16_t         m_sClientPort;
    string           m_strIFaceAddr;
    uint16_t         m_sIFacePort;

    bool             m_bSelfDelete;

    function<void(TcpSocket*)> m_fBytesReceived;
    function<void(TcpSocket*,void*)> m_fBytesReceivedParam;
    function<void(TcpSocketImpl*)> m_fClientConnectedSsl;
};

class TcpServerImpl : public BaseSocketImpl
{
public:
    TcpServerImpl(BaseSocket* pBkRef) noexcept;
    ~TcpServerImpl();
    TcpServerImpl() = delete;
    TcpServerImpl(const TcpServerImpl&) = delete;
    TcpServerImpl(TcpServerImpl&&) = delete;
    TcpServerImpl& operator=(const TcpServerImpl&) = delete;
    TcpServerImpl& operator=(TcpServerImpl&&) = delete;

    bool Start(const char* const szIpAddr, const uint16_t sPort);
    uint16_t GetServerPort();
    virtual void BindNewConnection(function<void(const vector<TcpSocket*>&)>) noexcept;
    virtual void BindNewConnection(function<void(const vector<TcpSocket*>&, void*)>) noexcept;
    void Close() noexcept override;

protected:
    void SetSocketOption(const SOCKET& fd) override;
    virtual TcpSocket* MakeClientConnection(const SOCKET&);

private:
    void Delete();
    void SelectThread();

protected:
    vector<SOCKET> m_vSockAccept;
    mutex          m_mtAcceptList;

private:
    vector<SOCKET> m_vSock;
    function<void(const vector<TcpSocket*>&)> m_fNewConnection;
    function<void(const vector<TcpSocket*>&, void*)> m_fNewConnectionParam;
};

class UdpSocketImpl : public BaseSocketImpl
{
protected:
    typedef tuple<unique_ptr<uint8_t[]>, size_t, string> DATA;

public:
    explicit UdpSocketImpl(BaseSocket* pBkRef);
    ~UdpSocketImpl();
    UdpSocketImpl() = delete;
    UdpSocketImpl(const UdpSocketImpl&) = delete;
    UdpSocketImpl(UdpSocketImpl&&) = delete;
    UdpSocketImpl& operator=(const UdpSocketImpl&) = delete;
    UdpSocketImpl& operator=(UdpSocketImpl&&) = delete;

    virtual bool Create(const char* const szIpToWhere, const uint16_t uint16_t, const char* const szIpToBind = nullptr);
    virtual bool EnableBroadCast(bool bEnable = true) noexcept;
    virtual bool AddToMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex) noexcept;
    virtual bool RemoveFromMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex) noexcept;
    virtual size_t Read(void* buf, size_t len, string& strFrom);
    virtual size_t Write(const void* buf, size_t len, const string& strTo);
    void Close() override;
    virtual size_t GetBytesAvailable() const noexcept;
    virtual size_t GetOutBytesInQue() const noexcept;
    virtual function<void(UdpSocket*)> BindFuncBytesReceived(function<void(UdpSocket*)> fBytesReceived) noexcept;
    virtual function<void(UdpSocket*, void*)> BindFuncBytesReceived(function<void(UdpSocket*, void*)> fBytesReceived) noexcept;

protected:
    void TriggerWriteThread();

private:
    void WriteThread();
    void SelectThread();

protected:
    function<int(const uint8_t*, size_t, const string&)> m_fnSslDecode;
    mutex            m_mxInDeque;
    deque<DATA>      m_quInData;
    atomic<size_t>  m_atInBytes;
    function<int(const uint8_t*, size_t, const string&)> m_fnSslEncode;
    mutex            m_mxOutDeque;
    deque<DATA>      m_quOutData;
    atomic<size_t>   m_atOutBytes;

private:
    bool             m_bCloseReq;
    mutex            m_mxWrite;
    condition_variable m_cv;

    function<void(UdpSocket*)> m_fBytesReceived;
    function<void(UdpSocket*, void*)> m_fBytesReceivedParam;
};

#endif  // #ifndef STDSOCKET_H
