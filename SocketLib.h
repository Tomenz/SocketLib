/* Copyright (C) 2016-2020 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
*/

#pragma once
#ifndef SOCKETLIB
#define SOCKETLIB
#include <memory>
#include <functional>
#include <vector>
#include <string>

using namespace std;

class TcpServer;
class BaseSocketImpl;
class TcpSocketImpl;
class SslTcpSocketImpl;

class BaseSocket
{
public:
    BaseSocket() = default;
    virtual ~BaseSocket();
    BaseSocket(const BaseSocket&) = delete;
    BaseSocket(BaseSocket&&) = delete;
    BaseSocket& operator=(const BaseSocket&) = delete;
    BaseSocket& operator=(BaseSocket&&) = delete;

    virtual void Close() = 0;
    virtual int GetErrorNo() const noexcept;
    virtual int GetErrorLoc() const noexcept;

    virtual function<void(BaseSocket*)> BindErrorFunction(function<void(BaseSocket*)> fError);
    virtual function<void(BaseSocket*, void*)> BindErrorFunction(function<void(BaseSocket*, void*)> fError);
    virtual function<void(BaseSocket*)> BindCloseFunction(function<void(BaseSocket*)> fCloseing);
    virtual function<void(BaseSocket*, void*)> BindCloseFunction(function<void(BaseSocket*, void*)> fCloseing);
    virtual void SetCallbackUserData(void* pUserData) noexcept;
    virtual void SetErrorNo(int iErrNo) noexcept;
    virtual uint16_t GetSocketPort();
    static int EnumIpAddresses(function<int(int, const string&, int, void*)> fnCallBack, void* vpUser);
    static void SetAddrNotifyCallback(const function<void(bool, const string&, int, int)>& fnCbAddrNotify);
    virtual void SetSocketName(const string& strName);
    virtual string& GetSocketName() noexcept;

    static void SetTrafficDebugCallback(function<void(const uint16_t, const char*, size_t, bool)> fnCbTrafficDbg);
    static size_t GetNrOfClientSockets();

protected:
    friend class SslTcpSocketImpl;
    BaseSocketImpl* GetImpl() const noexcept;
    unique_ptr<BaseSocketImpl> Impl_;
};

class TcpSocket : public BaseSocket
{
    friend class TcpServerImpl;
    friend class SslTcpSocket;
public:
    explicit TcpSocket();
    ~TcpSocket() = default;
    TcpSocket(const TcpSocket&) = delete;
    TcpSocket(TcpSocket&&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;
    TcpSocket& operator=(TcpSocket&&) = delete;

    virtual bool Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint = 0);
    virtual size_t Read(void* buf, size_t len);
    virtual size_t PutBackRead(void* buf, size_t len);
    virtual size_t Write(const void* buf, size_t len);
    void StartReceiving();
    void Close() override;
    virtual void SelfDestroy();
    virtual void Delete();
    virtual size_t GetBytesAvailable() const noexcept;
    virtual size_t GetOutBytesInQue() const noexcept;
    virtual function<void(TcpSocket*)> BindFuncBytesReceived(function<void(TcpSocket*)> fBytesReceived);
    virtual function<void(TcpSocket*, void*)> BindFuncBytesReceived(function<void(TcpSocket*, void*)> fBytesReceived);
    virtual function<void(TcpSocket*)> BindFuncConEstablished(function<void(TcpSocket*)> fClientConnected);
    virtual function<void(TcpSocket*, void*)> BindFuncConEstablished(function<void(TcpSocket*, void*)> fClientConnected);
    virtual bool IsSslConnection() const noexcept;

    const string& GetClientAddr() const noexcept;
    uint16_t GetClientPort() const noexcept;
    const string& GetInterfaceAddr() const noexcept;
    uint16_t GetInterfacePort() const noexcept;

    const TcpServer* GetServerSocketRef() const noexcept;

protected:
    explicit TcpSocket(bool/*bDummy*/) noexcept;
};

class TcpServer : public BaseSocket
{
    friend class TcpSocket;
public:
    explicit TcpServer();
    ~TcpServer() = default;
    TcpServer(const TcpServer&) = delete;
    TcpServer(TcpServer&&) = delete;
    TcpServer& operator=(const TcpServer&) = delete;
    TcpServer& operator=(TcpServer&&) = delete;

    bool Start(const char* const szIpAddr, const uint16_t sPort);
    uint16_t GetServerPort();
    virtual void BindNewConnection(function<void(const vector<TcpSocket*>&)>);
    virtual void BindNewConnection(function<void(const vector<TcpSocket*>&, void*)>);
    void Close() noexcept override;
protected:
    explicit TcpServer(bool/*bDummy*/) noexcept;
};

class UdpSocket : public BaseSocket
{
public:
    explicit UdpSocket();
    ~UdpSocket() = default;
    UdpSocket(const UdpSocket &t) = delete;
    UdpSocket(UdpSocket&&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;
    UdpSocket& operator=(UdpSocket&&) = delete;

    virtual bool Create(const char* const szIpToWhere, const uint16_t sPort, const char* const szIpToBind = nullptr);
    virtual bool EnableBroadCast(bool bEnable = true) noexcept;
    virtual bool AddToMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex) noexcept;
    virtual bool RemoveFromMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex) noexcept;
    virtual size_t Read(void* buf, size_t len, string& strFrom);
    virtual size_t Write(const void* buf, size_t len, const string& strTo);
    void Close() override;
    virtual size_t GetBytesAvailable() const noexcept;
    virtual size_t GetOutBytesInQue() const noexcept;
    virtual function<void(UdpSocket*)> BindFuncBytesReceived(function<void(UdpSocket*)> fBytesReceived);
    virtual function<void(UdpSocket*, void*)> BindFuncBytesReceived(function<void(UdpSocket*, void*)> fBytesReceived);
};

#ifndef WITHOUT_OPENSSL

class SslTcpSocket : public TcpSocket
{
    friend class SslTcpServerImpl;
public:
    explicit SslTcpSocket();
    explicit SslTcpSocket(const TcpSocket*);    // Switch from Tcp to Ssl/Tls
    ~SslTcpSocket() = default;
    SslTcpSocket(const SslTcpSocket&) = delete;
    SslTcpSocket(SslTcpSocket&&) = delete;
    SslTcpSocket& operator=(const SslTcpSocket&) = delete;
    SslTcpSocket& operator=(SslTcpSocket&&) = delete;

    bool AddServerCertificat(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey, const char* szDhParamFileName);
    bool AddCertificat(const char* const szHostCertificate, const char* const szHostKey);
    bool SetCipher(const char* const szCipher) noexcept;
    bool SetAcceptState();
    bool SetConnectState();
    bool Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint = 0) override;
    void Close() override;
    function<void(TcpSocket*)> BindFuncConEstablished(function<void(TcpSocket*)> fClientConnected) override;
    function<void(TcpSocket*, void*)> BindFuncConEstablished(function<void(TcpSocket*, void*)> fClientConnected) override;
    bool IsSslConnection() const noexcept override;

    void SetAlpnProtokollNames(const vector<string>& vProtoList);
    const string GetSelAlpnProtocol() const;
    void SetTrustedRootCertificates(const char* const szTrustRootCert);
    long CheckServerCertificate(const char* const szHostName);

    static SslTcpSocket* SwitchToSll(TcpSocket*);
};

class SslTcpServer : public TcpServer
{
public:
    explicit SslTcpServer();
    ~SslTcpServer() = default;
    SslTcpServer(const SslTcpServer&) = delete;
    SslTcpServer(SslTcpServer&&) = delete;
    SslTcpServer& operator=(const SslTcpServer&) = delete;
    SslTcpServer& operator=(SslTcpServer&&) = delete;

    bool AddCertificat(const char* const szCAcertificate, const char* const szHostCertificate, const char* const szHostKey);
    bool SetDHParameter(const char* const szDhParamFileName);
    bool SetCipher(const char* const szCipher) noexcept;
    void SetAlpnProtokollNames(const vector<string>& vProtoList);
};

class SslUdpSocket : public UdpSocket
{
public:
    explicit SslUdpSocket();
    ~SslUdpSocket() = default;
    SslUdpSocket(const SslUdpSocket&) = delete;
    SslUdpSocket(SslUdpSocket&&) = delete;
    SslUdpSocket& operator=(const SslUdpSocket&) = delete;
    SslUdpSocket& operator=(SslUdpSocket&&) = delete;

    bool AddCertificat(const char* const szHostCertificate, const char* const szHostKey);
    bool CreateServerSide(const char* const szIpToWhere, const uint16_t uint16_t, const char* const szIpToBind = nullptr);
    bool CreateClientSide(const char* const szIpToWhere, const uint16_t uint16_t, const char* const szDestAddr, const char* const szIpToBind = nullptr);
    void Close() override;
    function<void(UdpSocket*)> BindFuncSslInitDone(function<void(UdpSocket*)> fSllInitDone);
    function<void(UdpSocket*, void*)> BindFuncSslInitDone(function<void(UdpSocket*, void*)> fSllInitDone);
};

#endif // WITHOUT_OPENSSL

#endif // SOCKETLIB
