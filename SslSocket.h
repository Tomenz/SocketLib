/* Copyright (C) 2016-2020 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
*/

#ifndef SSLSOCKET_H
#define SSLSOCKET_H

#ifndef WITHOUT_OPENSSL

#include "StdSocket.h"
#include "OpenSSLWraper.h"

using namespace OpenSSLWrapper;

class SslTcpSocketImpl : public TcpSocketImpl
{
public:
    explicit SslTcpSocketImpl(BaseSocket*);
    explicit SslTcpSocketImpl(BaseSocket* pBkref, TcpSocketImpl* pTcpSocket);   // Switch from Tcp to Ssl/Tls
    ~SslTcpSocketImpl();
    SslTcpSocketImpl() = delete;
    SslTcpSocketImpl(const SslTcpSocketImpl&) = delete;
    SslTcpSocketImpl(SslTcpSocketImpl&&) = delete;
    SslTcpSocketImpl& operator=(const SslTcpSocketImpl&) = delete;
    SslTcpSocketImpl& operator=(SslTcpSocketImpl&&) = delete;

    bool AddServerCertificate(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey, const char* szDhParamFileName);
    bool AddCertificate(const char* const szHostCertificate, const char* const szHostKey);
    bool SetCipher(const char* const szCipher) noexcept;
    bool SetAcceptState();
    bool SetConnectState();
    bool Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint = AF_UNSPEC) override;
    void Close() override;
    function<void(TcpSocket*)> BindFuncConEstablished(function<void(TcpSocket*)> fClientConnected) noexcept override;
    function<void(TcpSocket*, void*)> BindFuncConEstablished( function<void(TcpSocket*, void*)> fClientConnected) noexcept override;
    bool IsSslConnection() const noexcept override { return true; }

    void SetAlpnProtokollNames(const vector<string>& vProtoList);
    const string GetSelAlpnProtocol() const;
    void SetTrustedRootCertificates(const char* const szTrustRootCert);
    long CheckServerCertificate(const char* const szHostName);

    static SslTcpSocket* SwitchToSsl(TcpSocket*);

private:
    friend class SslTcpServerImpl;    // The Server class needs access to the private constructor in the next line
    void ConEstablished(const TcpSocketImpl* const pTcpSocket);
    int DatenEncode(const uint8_t* buffer, size_t nAnzahl);
    int DatenDecode(const uint8_t* buffer, size_t nAnzahl, bool& bZeroReceived);

    static const string& fnForwarder(void* obj) noexcept { return static_cast<SslTcpSocketImpl*>(obj)->GetInterfaceAddr(); }

private:
    SslClientContext m_pClientCtx;
    vector<SslServerContext>  m_pServerCtx;
    unique_ptr<SslConnection>  m_pSslCon;
    function<void(TcpSocket*)> m_fClientConnected;
    function<void(TcpSocket*, void*)> m_fClientConnectedParam;

    bool             m_bCloseReq;
    int              m_iSslInit;
    vector<string>   m_vProtoList;
    string           m_strTrustRootCert;

    mutex            m_mxEnDecode;
};

class SslTcpServerImpl : public TcpServerImpl
{
public:
    SslTcpServerImpl(BaseSocket*) noexcept;
    ~SslTcpServerImpl() = default;
    SslTcpServerImpl() = delete;
    SslTcpServerImpl(const SslTcpServerImpl&) = delete;
    SslTcpServerImpl(SslTcpServerImpl&&) = delete;
    SslTcpServerImpl& operator=(const SslTcpServerImpl&) = delete;
    SslTcpServerImpl& operator=(SslTcpServerImpl&&) = delete;

    SslTcpSocket* MakeClientConnection(const SOCKET&) override;
    bool AddCertificate(const char* const szCAcertificate, const char* const szHostCertificate, const char* const szHostKey);
    bool SetDHParameter(const char* const szDhParamFileName);
    bool SetCipher(const char* const szCipher) noexcept;
    void SetAlpnProtokollNames(const vector<string>& vStrProtoNames);

private:
    vector<SslServerContext> m_SslCtx;
};

class SslUdpSocketImpl : public UdpSocketImpl
{
public:
    explicit SslUdpSocketImpl(BaseSocket* pBkRef);
    ~SslUdpSocketImpl();
    SslUdpSocketImpl() = delete;
    SslUdpSocketImpl(const SslUdpSocketImpl&) = delete;
    SslUdpSocketImpl(SslUdpSocketImpl&&) = delete;
    SslUdpSocketImpl& operator=(const SslUdpSocketImpl&) = delete;
    SslUdpSocketImpl& operator=(SslUdpSocketImpl&&) = delete;

    bool AddCertificate(const char* const szHostCertificate, const char* const szHostKey);
    bool CreateServerSide(const char* const szIpToWhere, const uint16_t sPort, const char* const szIpToBind = nullptr);
    bool CreateClientSide(const char* const szIpToWhere, const uint16_t sPort, const char* const szDestAddr, const char* const szIpToBind = nullptr);
    void Close() override;
    function<void(UdpSocket*)> BindFuncSslInitDone(function<void(UdpSocket*)> fSllInitDone) noexcept;
    function<void(UdpSocket*, void*)> BindFuncSslInitDone(function<void(UdpSocket*, void*)> fSllInitDone) noexcept;

private:
    int DatenEncode(const uint8_t* buf, size_t nAnzahl, const string& strAddress);
    int DatenDecode(const uint8_t* buffer, size_t nAnzahl, const string& strAddress);

private:
    SslUdpContext            m_pUdpCtx;
    unique_ptr<SslConnection> m_pSslCon;

    function<void(UdpSocket*)> m_fSllInitDone;
    function<void(UdpSocket*, void*)> m_fSllInitDoneParam;

    bool             m_bCloseReq;
    string           m_strDestAddr;

    mutex            m_mxEnDecode;
};

#endif  // WITHOUT_OPENSSL

#endif  // #ifndef SSLSOCKET_H
