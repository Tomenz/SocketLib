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
class TcpServerImpl;
class UdpSocketImpl;
class SslTcpSocketImpl;
class SslTcpServerImpl;

class BaseSocket
{
public:
    virtual ~BaseSocket();
    //BaseSocket(BaseSocket &&) noexcept;
    //BaseSocket& operator=(BaseSocket &&) noexcept;

    virtual void Close() = 0;
    virtual void SelfDestroy() noexcept { static_assert(true, "class has no self destroy function"); }
    virtual int GetErrorNo() const  noexcept;
    virtual int GetErrorLoc() const  noexcept;

    virtual function<void(BaseSocket*)> BindErrorFunction(function<void(BaseSocket*)> fError) noexcept;
    virtual function<void(BaseSocket*, void*)> BindErrorFunction(function<void(BaseSocket*, void*)> fError) noexcept;
    virtual function<void(BaseSocket*)> BindCloseFunction(function<void(BaseSocket*)> fCloseing) noexcept;
    virtual function<void(BaseSocket*, void*)> BindCloseFunction(function<void(BaseSocket*, void*)> fCloseing) noexcept;
    virtual void SetCallbackUserData(void* pUserData);
    virtual void SetErrorNo(int iErrNo) noexcept;
    virtual uint16_t GetSocketPort();
    static int EnumIpAddresses(function<int(int, const string&, int, void*)> fnCallBack, void* vpUser);
    static void SetAddrNotifyCallback(function<void(bool, const string&, int, int)>& fnCbAddrNotify);

    static void SetTraficDebugCallback(function<void(const uint16_t, const char*, size_t, bool)> fnCbTraficDbg);

protected:
    explicit BaseSocket(BaseSocketImpl* pImpl);
    void SetImpl(BaseSocketImpl* pImpl);
    BaseSocketImpl* GetImpl();
    unique_ptr<BaseSocketImpl> Impl_;
};

class TcpSocket : public BaseSocket
{
    friend class TcpServerImpl;
    friend class SslTcpSocket;
public:
    explicit TcpSocket();
    virtual ~TcpSocket();
    //TcpSocket(TcpSocket &&) noexcept;
    //TcpSocket& operator=(TcpSocket &&) noexcept;

    virtual bool Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint = 0);
    virtual size_t Read(void* buf, size_t len);
    virtual size_t PutBackRead(void* buf, size_t len);
    virtual size_t Write(const void* buf, size_t len);
    void StartReceiving();
    virtual void Close() noexcept;
    virtual void SelfDestroy() noexcept override;
    virtual void Delete() noexcept;
    virtual size_t GetBytesAvailible() const noexcept;
    virtual size_t GetOutBytesInQue() const noexcept;
    virtual function<void(TcpSocket*)> BindFuncBytesReceived(function<void(TcpSocket*)> fBytesReceived) noexcept;
    virtual function<void(TcpSocket*, void*)> BindFuncBytesReceived(function<void(TcpSocket*, void*)> fBytesReceived) noexcept;
    virtual function<void(TcpSocket*)> BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted) noexcept;
    virtual function<void(TcpSocket*, void*)> BindFuncConEstablished(function<void(TcpSocket*, void*)> fClientConneted) noexcept;
    virtual bool IsSslConnection() const noexcept;

    const string& GetClientAddr() const noexcept;
    uint16_t GetClientPort() const noexcept;
    const string& GetInterfaceAddr() const noexcept;
    uint16_t GetInterfacePort() const noexcept;

    const TcpServer* GetServerSocketRef() const noexcept;

protected:
    explicit TcpSocket(TcpSocketImpl* const);
};

class TcpServer : public BaseSocket
{
    friend class TcpSocket;
public:
    explicit TcpServer();
    virtual ~TcpServer();
    //TcpServer(TcpServer &&) noexcept;
    //TcpServer& operator=(TcpServer &&) noexcept;
    bool Start(const char* const szIpAddr, const uint16_t sPort);
    uint16_t GetServerPort();
    virtual void BindNewConnection(function<void(const vector<TcpSocket*>&)>) noexcept;
    virtual void BindNewConnection(function<void(const vector<TcpSocket*>&, void*)>) noexcept;
    virtual void Close() noexcept;
protected:
    explicit TcpServer(TcpServerImpl* const);
};

class UdpSocket : public BaseSocket
{
public:
    explicit UdpSocket();
    virtual ~UdpSocket();
    UdpSocket(const UdpSocket &t) = delete;
    UdpSocket& operator=(const UdpSocket &t) = delete;
    //UdpSocket(UdpSocket &&) noexcept;
    //UdpSocket& operator=(UdpSocket &&) noexcept;

    virtual bool Create(const char* const szIpToWhere, const uint16_t sPort, const char* const szIpToBind = nullptr);
    virtual bool EnableBroadCast(bool bEnable = true);
    virtual bool AddToMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex);
    virtual bool RemoveFromMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex);
    virtual size_t Read(void* buf, size_t len, string& strFrom);
    virtual size_t Write(const void* buf, size_t len, const string& strTo);
    virtual void Close() noexcept;
    virtual size_t GetBytesAvailible() const noexcept;
    virtual size_t GetOutBytesInQue() const noexcept;
    virtual function<void(UdpSocket*)> BindFuncBytesReceived(function<void(UdpSocket*)> fBytesReceived) noexcept;
    virtual function<void(UdpSocket*, void*)> BindFuncBytesReceived(function<void(UdpSocket*, void*)> fBytesReceived) noexcept;
protected:
    explicit UdpSocket(UdpSocketImpl* const);
};

#ifndef WITHOUT_OPENSSL

class SslTcpSocket : public TcpSocket
{
    friend class SslTcpServerImpl;
public:
    explicit SslTcpSocket();
    explicit SslTcpSocket(TcpSocket* pTcpSocket);
    virtual ~SslTcpSocket();
    //SslTcpSocket(SslTcpSocket &&) noexcept;;
    //SslTcpSocket& operator=(SslTcpSocket &&) noexcept;
    bool AddServerCertificat(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey, const char* szDhParamFileName);
    bool AddCertificat(const char* const szHostCertificate, const char* const szHostKey);
    bool SetCipher(const char* const szCipher);
    bool SetAcceptState();
    bool SetConnectState();
    bool Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint = 0) override;
    void Close() noexcept override;
    virtual function<void(TcpSocket*)> BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted) noexcept;
    virtual function<void(TcpSocket*, void*)> BindFuncConEstablished(function<void(TcpSocket*, void*)> fClientConneted) noexcept;
    bool IsSslConnection() const noexcept override;

    void SetAlpnProtokollNames(vector<string>& vProtoList);
    const string GetSelAlpnProtocol() const;
    void SetTrustedRootCertificates(const char* const szTrustRootCert);
    long CheckServerCertificate(const char* const szHostName);

protected:
    explicit SslTcpSocket(SslTcpSocketImpl* const);
};

class SslTcpServer : public TcpServer
{
public:
    explicit SslTcpServer();
    virtual ~SslTcpServer();
    bool AddCertificat(const char* const szCAcertificate, const char* const szHostCertificate, const char* const szHostKey);
    bool SetDHParameter(const char* const szDhParamFileName);
    bool SetCipher(const char* const szCipher);
    void SetAlpnProtokollNames(vector<string>& vProtoList);
};

class SslUdpSocket : public UdpSocket
{
public:
    explicit SslUdpSocket();
    bool AddCertificat(const char* const szHostCertificate, const char* const szHostKey);
    bool CreateServerSide(const char* const szIpToWhere, const uint16_t uint16_t, const char* const szIpToBind = nullptr);
    bool CreateClientSide(const char* const szIpToWhere, const uint16_t uint16_t, const char* const szDestAddr, const char* const szIpToBind = nullptr);
    void Close() noexcept override;
    function<void(UdpSocket*)> BindFuncSslInitDone(function<void(UdpSocket*)> fSllInitDone) noexcept;
    function<void(UdpSocket*, void*)> BindFuncSslInitDone(function<void(UdpSocket*, void*)> fSllInitDone) noexcept;
};

#endif // WITHOUT_OPENSSL

#endif // SOCKETLIB
