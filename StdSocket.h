/* Copyright (C) 2016-2019 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
*/

#pragma once
#ifndef STDSOCKET
#define STDSOCKET

#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <functional>

#if defined (_WIN32) || defined (_WIN64)
// https://support.microsoft.com/de-de/kb/257460
//#include <winsock2.h>
#include <Ws2tcpip.h>
#include <Netioapi.h>
#else
#include <thread>
#include <condition_variable>
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
    static InitSocket* GetInstance();
    ~InitSocket();
    void SetAddrNotifyCallback(function<void(bool, const string&, int, int)>& fnCbAddrNotify);

private:
    InitSocket();
#if defined (_WIN32) || defined (_WIN64)
    static VOID __stdcall IpIfaceChanged(PVOID CallerContext, PMIB_IPINTERFACE_ROW Row, MIB_NOTIFICATION_TYPE NotificationType);
    HANDLE m_hIFaceNotify;
#else
    void IpChangeThread();
    thread m_thIpChange;
    bool   m_bStopThread;
#endif
    int CbEnumIpAdressen(int iFamiely, const string& strIp, int nInterFaceId, void* vpUserParam);
    void NotifyOnAddressChanges(vector<tuple<string, int, int>>& vNewListing);

    vector<tuple<string, int, int>> m_vCurIPAddr;
    mutex m_mxCurIpAddr;
    function<void(bool, const string&, int, int)> m_fnCbAddrNotify;
};

class BaseSocketImpl
{
public:
    explicit BaseSocketImpl();
    virtual ~BaseSocketImpl();
    virtual void Close() = 0;
    virtual void SelfDestroy() = 0;
    virtual function<void(BaseSocket*)> BindErrorFunction(function<void(BaseSocket*)> fError) noexcept;
    virtual function<void(BaseSocket*)> BindCloseFunction(function<void(BaseSocket*)> fCloseing) noexcept;
    virtual int GetErrorNo() const  noexcept { return m_iError; }
    virtual int GetErrorLoc() const  noexcept { return m_iErrLoc; }
    virtual void SetErrorNo(int iErrNo) noexcept { m_iError = iErrNo; }
    virtual uint16_t GetSocketPort();
    static int EnumIpAddresses(function<int(int,const string&,int,void*)> fnCallBack, void* vpUser);
    static void SetAddrNotifyCallback(function<void(bool, const string&, int, int)>& fnCbAddrNotify);

protected:
    explicit BaseSocketImpl(BaseSocketImpl* pBaseSocket);
    virtual void SetSocketOption(const SOCKET& fd);
    virtual void OnError();
    virtual void StartCloseingCB();

protected:
    SOCKET                      m_fSock;
    thread                      m_thListen;
    thread                      m_thWrite;
    bool                        m_bStop;
    int                         m_iError;
    int                         m_iErrLoc;
    atomic_uchar                m_iShutDownState;
    function<void(BaseSocket*)> m_fError;
    function<void(BaseSocket*)> m_fCloseing;
    mutex                       m_mxFnClosing;
    BaseSocket*                 m_pBkRef;

private:
    static atomic_uint s_atRefCount;
};

class TcpSocketImpl : public BaseSocketImpl
{
protected:
    typedef tuple<shared_ptr<uint8_t>, uint32_t> DATA;

public:
    TcpSocketImpl(BaseSocket* pBkRef);
    virtual ~TcpSocketImpl();
    virtual bool Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint = AF_UNSPEC);
    virtual uint32_t Read(void* buf, uint32_t len);
    virtual uint32_t PutBackRead(void* buf, uint32_t len);
    virtual size_t Write(const void* buf, size_t len);
    void StartReceiving();
    virtual void Close() noexcept;
    virtual void SelfDestroy() noexcept;
    virtual void Delete() noexcept;
    virtual uint32_t GetBytesAvailible() const noexcept;
    virtual uint32_t GetOutBytesInQue() const noexcept;
    virtual function<void(TcpSocket*)> BindFuncBytesReceived(function<void(TcpSocket*)> fBytesReceived) noexcept;
    virtual function<void(TcpSocket*)> BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted) noexcept;
    virtual bool IsSslConnection() const noexcept { return false; }

    const string& GetClientAddr() const noexcept { return m_strClientAddr; }
    uint16_t GetClientPort() const noexcept { return m_sClientPort; }
    const string& GetInterfaceAddr() const noexcept { return m_strIFaceAddr; }
    uint16_t GetInterfacePort() const noexcept { return m_sIFacePort; }

    const TcpServer* GetServerSocketRef() const noexcept { return m_pRefServSocket; }

protected:
    friend TcpServerImpl;   // The Server class needs access to the private constructor in the next line
    explicit TcpSocketImpl(const SOCKET, const TcpServer* pRefServSocket);
    explicit TcpSocketImpl(BaseSocket* pBkRef, TcpSocketImpl* pTcpSocketImpl);
    virtual void SetSocketOption(const SOCKET& fd);
    void TriggerWriteThread();
    void BindFuncConEstablished(function<void(TcpSocketImpl*)> fClientConneted) noexcept;
    bool GetConnectionInfo();

private:
    void WriteThread();
    void SelectThread();
    void ConnectThread();

protected:
    function<int(const char*, uint32_t)> m_fnSslDecode;
    mutex            m_mxInDeque;
    deque<DATA>      m_quInData;
    atomic<uint32_t> m_atInBytes;

    function<int(const void*, uint32_t)> m_fnSslEncode;
    mutex            m_mxOutDeque;
    deque<DATA>      m_quOutData;
    atomic<uint32_t> m_atOutBytes;

private:
    thread           m_thConnect;

    bool             m_bCloseReq;
    mutex            m_mxWrite;
    condition_variable m_cv;

    string           m_strClientAddr;
    uint16_t         m_sClientPort;
    string           m_strIFaceAddr;
    uint16_t         m_sIFacePort;

    const TcpServer* m_pRefServSocket;
    bool             m_bSelfDelete;

    function<void(TcpSocket*)> m_fBytesReceived;
    function<void(TcpSocket*)> m_fClientConneted;
    function<void(TcpSocketImpl*)> m_fClientConnetedSsl;
};

class TcpServerImpl : public BaseSocketImpl
{
public:
    TcpServerImpl(BaseSocket* pBkRef);
    virtual ~TcpServerImpl();
    bool Start(const char* const szIpAddr, const uint16_t sPort);
    uint16_t GetServerPort();
    void BindNewConnection(const function<void(const vector<TcpSocket*>&)>&) noexcept;
    virtual void Close() noexcept;
    virtual void SelfDestroy() noexcept override { static_assert(true, "class has no self destroy function"); }
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

class UdpSocketImpl : public BaseSocketImpl
{
protected:
    typedef tuple<shared_ptr<uint8_t>, uint32_t, string> DATA;

public:
    explicit UdpSocketImpl(BaseSocket* pBkRef);
    virtual ~UdpSocketImpl();
    virtual bool Create(const char* const szIpToWhere, const uint16_t uint16_t, const char* const szIpToBind = nullptr);
    virtual bool EnableBroadCast(bool bEnable = true);
    virtual bool AddToMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex);
    virtual bool RemoveFromMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex);
    virtual uint32_t Read(void* buf, uint32_t len, string& strFrom);
    virtual size_t Write(const void* buf, size_t len, const string& strTo);
    virtual void Close() noexcept;
    virtual void SelfDestroy() noexcept override { static_assert(true, "class has no self destroy function"); }
    virtual uint32_t GetBytesAvailible() const noexcept;
    virtual uint32_t GetOutBytesInQue() const noexcept;
    virtual function<void(UdpSocket*)> BindFuncBytesReceived(function<void(UdpSocket*)> fBytesReceived) noexcept;

protected:
    void TriggerWriteThread();

private:
    void WriteThread();
    void SelectThread();

protected:
    function<int(const char*, uint32_t, const string&)> m_fnSslDecode;
    mutex            m_mxInDeque;
    deque<DATA>      m_quInData;
    atomic<uint32_t> m_atInBytes;
    function<int(const void*, uint32_t, const string&)> m_fnSslEncode;
    mutex            m_mxOutDeque;
    deque<DATA>      m_quOutData;
    atomic<uint32_t> m_atOutBytes;

private:
    bool             m_bCloseReq;
    mutex            m_mxWrite;
    condition_variable m_cv;

    function<void(UdpSocket*)> m_fBytesReceived;
};

#endif  // #ifndef STDSOCKET
