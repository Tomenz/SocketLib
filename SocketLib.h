/* Copyright (C) 2016-2020 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
*/

#ifndef SOCKETLIB_H
#define SOCKETLIB_H

#include <memory>
#include <functional>
#include <vector>
#include <string>

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

    virtual std::function<void(BaseSocket*)> BindErrorFunction(std::function<void(BaseSocket*)> fError);
    virtual std::function<void(BaseSocket*, void*)> BindErrorFunction(std::function<void(BaseSocket*, void*)> fError);
    virtual std::function<void(BaseSocket*)> BindCloseFunction(std::function<void(BaseSocket*)> fClosing);
    virtual std::function<void(BaseSocket*, void*)> BindCloseFunction(std::function<void(BaseSocket*, void*)> fClosing);
    virtual void SetCallbackUserData(void* pUserData) noexcept;
    virtual void SetErrorNo(int iErrNo) noexcept;
    virtual uint16_t GetSocketPort();
    static int EnumIpAddresses(std::function<int(int, const std::string&, int, void*)> fnCallBack, void* vpUser);
    static void SetAddrNotifyCallback(const std::function<void(bool, const std::string&, int, int)>& fnCbAddrNotify);
    virtual void SetSocketName(const std::string& strName);
    virtual std::string& GetSocketName() noexcept;

    static void SetTrafficDebugCallback(std::function<void(const uint16_t, const char*, size_t, bool)> fnCbTrafficDbg);
    static size_t GetNrOfClientSockets();

protected:
    friend class SslTcpSocketImpl;
    BaseSocketImpl* GetImpl() const noexcept;
    std::unique_ptr<BaseSocketImpl> Impl_;
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
    virtual std::function<void(TcpSocket*)> BindFuncBytesReceived(std::function<void(TcpSocket*)> fBytesReceived);
    virtual std::function<void(TcpSocket*, void*)> BindFuncBytesReceived(std::function<void(TcpSocket*, void*)> fBytesReceived);
    virtual std::function<void(TcpSocket*)> BindFuncConEstablished(std::function<void(TcpSocket*)> fClientConnected);
    virtual std::function<void(TcpSocket*, void*)> BindFuncConEstablished(std::function<void(TcpSocket*, void*)> fClientConnected);
    virtual bool IsSslConnection() const noexcept;

    const std::string& GetClientAddr() const noexcept;
    uint16_t GetClientPort() const noexcept;
    const std::string& GetInterfaceAddr() const noexcept;
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
    virtual void BindNewConnection(std::function<void(const std::vector<TcpSocket*>&)>);
    virtual void BindNewConnection(std::function<void(const std::vector<TcpSocket*>&, void*)>);
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
    virtual size_t Read(void* buf, size_t len, std::string& strFrom);
    virtual size_t Write(const void* buf, size_t len, const std::string& strTo);
    void Close() override;
    virtual size_t GetBytesAvailable() const noexcept;
    virtual size_t GetOutBytesInQue() const noexcept;
    virtual std::function<void(UdpSocket*)> BindFuncBytesReceived(std::function<void(UdpSocket*)> fBytesReceived);
    virtual std::function<void(UdpSocket*, void*)> BindFuncBytesReceived(std::function<void(UdpSocket*, void*)> fBytesReceived);
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

    bool AddServerCertificate(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey, const char* szDhParamFileName);
    bool AddCertificate(const char* const szHostCertificate, const char* const szHostKey);
    bool SetCipher(const char* const szCipher) noexcept;
    bool SetAcceptState();
    bool SetConnectState();
    bool Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint = 0) override;
    void Close() override;
    std::function<void(TcpSocket*)> BindFuncConEstablished(std::function<void(TcpSocket*)> fClientConnected) override;
    std::function<void(TcpSocket*, void*)> BindFuncConEstablished(std::function<void(TcpSocket*, void*)> fClientConnected) override;
    bool IsSslConnection() const noexcept override;

    void SetAlpnProtokollNames(const std::vector<std::string>& vProtoList);
    const std::string GetSelAlpnProtocol() const;
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

    bool AddCertificate(const char* const szCAcertificate, const char* const szHostCertificate, const char* const szHostKey);
    bool SetDHParameter(const char* const szDhParamFileName);
    bool SetCipher(const char* const szCipher) noexcept;
    void SetAlpnProtokollNames(const std::vector<std::string>& vProtoList);
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

    bool AddCertificate(const char* const szHostCertificate, const char* const szHostKey);
    bool CreateServerSide(const char* const szIpToWhere, const uint16_t uint16_t, const char* const szIpToBind = nullptr);
    bool CreateClientSide(const char* const szIpToWhere, const uint16_t uint16_t, const char* const szDestAddr, const char* const szIpToBind = nullptr);
    void Close() override;
    std::function<void(UdpSocket*)> BindFuncSslInitDone(std::function<void(UdpSocket*)> fSllInitDone);
    std::function<void(UdpSocket*, void*)> BindFuncSslInitDone(std::function<void(UdpSocket*, void*)> fSllInitDone);
};

#endif // WITHOUT_OPENSSL

#endif // SOCKETLIB_H
