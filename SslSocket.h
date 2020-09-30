/* Copyright (C) 2016-2020 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
*/

#pragma once
#ifndef SSLSOCKET
#define SSLSOCKET

#ifndef WITHOUT_OPENSSL

#include "StdSocket.h"
#include "OpenSSLWraper.h"

using namespace OpenSSLWrapper;

class SslTcpSocketImpl : public TcpSocketImpl
{
public:
    explicit SslTcpSocketImpl(BaseSocket*);
    explicit SslTcpSocketImpl(BaseSocket* pBkref, TcpSocketImpl* pTcpSocket);
    virtual ~SslTcpSocketImpl();
    bool AddServerCertificat(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey, const char* szDhParamFileName);
    bool AddCertificat(const char* const szHostCertificate, const char* const szHostKey);
    bool SetCipher(const char* const szCipher);
    bool SetAcceptState();
    bool SetConnectState();
    bool Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint = AF_UNSPEC) override;
    void Close() noexcept override;
    function<void(TcpSocket*)> BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted) noexcept;
    function<void(TcpSocket*, void*)> BindFuncConEstablished(function<void(TcpSocket*, void*)> fClientConneted) noexcept;
    bool IsSslConnection() const noexcept override { return true; }

    void SetAlpnProtokollNames(vector<string>& vProtoList);
    const string GetSelAlpnProtocol() const;
    void SetTrustedRootCertificates(const char* const szTrustRootCert);
    long CheckServerCertificate(const char* const szHostName);

private:
    friend SslTcpServerImpl;    // The Server class needs access to the private constructor in the next line
    explicit SslTcpSocketImpl(SslConnetion* pSslCon, const SOCKET fSock, const TcpServer* pRefServSocket);
    void ConEstablished(const TcpSocketImpl* const pTcpSocket);
    int DatenEncode(const void* buffer, size_t nAnzahl);
    int DatenDecode(const char* buffer, size_t nAnzahl);

    static const string& fnFoarwarder(void* obj) { return static_cast<SslTcpSocketImpl*>(obj)->GetInterfaceAddr(); }

private:
    SslClientContext m_pClientCtx;
    vector<SslServerContext>  m_pServerCtx;
    SslConnetion*    m_pSslCon;
    function<void(TcpSocket*)> m_fClientConneted;
    function<void(TcpSocket*, void*)> m_fClientConnetedParam;

    bool             m_bCloseReq;
    int              m_iSslInit;
    vector<string>   m_vProtoList;
    string           m_strTrustRootCert;

    mutex            m_mxEnDecode;
};

class SslTcpServerImpl : public TcpServerImpl
{
public:
    SslTcpServerImpl(BaseSocket*);
    SslTcpSocket* MakeClientConnection(const SOCKET&);
    bool AddCertificat(const char* const szCAcertificate, const char* const szHostCertificate, const char* const szHostKey);
    bool SetDHParameter(const char* const szDhParamFileName);
    bool SetCipher(const char* const szCipher);
    void SetAlpnProtokollNames(vector<string>& vStrProtoNames);

private:
    vector<SslServerContext> m_SslCtx;
};

class SslUdpSocketImpl : public UdpSocketImpl
{
public:
    explicit SslUdpSocketImpl(BaseSocket* pBkRef);
    virtual ~SslUdpSocketImpl();
    bool AddCertificat(const char* const szHostCertificate, const char* const szHostKey);
    bool CreateServerSide(const char* const szIpToWhere, const uint16_t sPort, const char* const szIpToBind = nullptr);
    bool CreateClientSide(const char* const szIpToWhere, const uint16_t sPort, const char* const szDestAddr, const char* const szIpToBind = nullptr);
    void Close() noexcept override;
    function<void(UdpSocket*)> BindFuncSslInitDone(function<void(UdpSocket*)> fSllInitDone) noexcept;
    function<void(UdpSocket*, void*)> BindFuncSslInitDone(function<void(UdpSocket*, void*)> fSllInitDone) noexcept;

private:
    int DatenEncode(const void* buf, size_t nAnzahl, const string& strAddress);
    int DatenDecode(const char* buffer, size_t nAnzahl, const string& strAddress);

private:
    SslUdpContext    m_pUdpCtx;
    SslConnetion*    m_pSslCon;

    function<void(UdpSocket*)> m_fSllInitDone;
    function<void(UdpSocket*, void*)> m_fSllInitDoneParam;

    bool             m_bCloseReq;
    string           m_strDestAddr;

    mutex            m_mxEnDecode;
};

#endif  // WITHOUT_OPENSSL

#endif  // #ifndef SSLSOCKET
