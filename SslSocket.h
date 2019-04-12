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
#ifndef SSLSOCKET
#define SSLSOCKET

#include "StdSocket.h"
#include "OpenSSLWraper.h"

using namespace OpenSSLWrapper;

class SslTcpServer;

class SslTcpSocket : public TcpSocket
{
public:
    explicit SslTcpSocket();
    explicit SslTcpSocket(TcpSocket* pTcpSocket);
    virtual ~SslTcpSocket();
    bool AddServerCertificat(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey, const char* szDhParamFileName);
    bool AddCertificat(const char* const szHostCertificate, const char* const szHostKey);
    bool SetCipher(const char* const szCipher);
    bool SetAcceptState();
    bool Connect(const char* const szIpToWhere, const uint16_t sPort) override;
    void Close() noexcept override;
    function<void(TcpSocket*)> BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted) noexcept override;
    bool IsSslConnection() const noexcept override { return true; }

    void SetAlpnProtokollNames(vector<string>& vProtoList);
    const string GetSelAlpnProtocol() const;
    void SetTrustedRootCertificates(const char* const szTrustRootCert);
    long CheckServerCertificate(const char* const szHostName);

private:
    friend SslTcpServer;
    explicit SslTcpSocket(SslConnetion* pSslCon, const SOCKET fSock, const TcpServer* pRefServSocket);
    void ConEstablished(const TcpSocket* const pTcpSocket);
    int DatenEncode(const void* buffer, uint32_t nAnzahl);
    int DatenDecode(const char* buffer, uint32_t nAnzahl);

    static const string& fnFoarwarder(void* obj) { return static_cast<SslTcpSocket*>(obj)->GetInterfaceAddr(); }

private:
    SslClientContext m_pClientCtx;
    vector<SslServerContext>  m_pServerCtx;
    SslConnetion*    m_pSslCon;
    function<void(TcpSocket*)> m_fClientConneted;

    bool             m_bCloseReq;
    int              m_iSslInit;
    vector<string>   m_vProtoList;
    string           m_strTrustRootCert;
};

class SslTcpServer : public TcpServer
{
public:
    SslTcpSocket* const MakeClientConnection(const SOCKET&);
    bool AddCertificat(const char* const szCAcertificate, const char* const szHostCertificate, const char* const szHostKey);
    bool SetDHParameter(const char* const szDhParamFileName);
    bool SetCipher(const char* const szCipher);

private:
    vector<SslServerContext> m_SslCtx;
};

class SslUdpSocket : public UdpSocket
{
public:
    explicit SslUdpSocket();
    virtual ~SslUdpSocket();
    bool AddCertificat(const char* const szHostCertificate, const char* const szHostKey);
    bool CreateServerSide(const char* const szIpToWhere, const short sPort, const char* const szIpToBind = nullptr);
    bool CreateClientSide(const char* const szIpToWhere, const short sPort, const char* const szDestAddr, const char* const szIpToBind = nullptr);
    void Close() noexcept override;
    function<void(UdpSocket*)> BindFuncSslInitDone(function<void(UdpSocket*)> fSllInitDone) noexcept;

private:
    int DatenEncode(const void* buf, uint32_t nAnzahl, const string& strAddress);
    int DatenDecode(const char* buffer, uint32_t nAnzahl, const string& strAddress);

//    static void ssl_info_callbackServer(const SSL* ssl, int where, int ret);
//    static void ssl_info_callbackClient(const SSL* ssl, int where, int ret);

private:
    SslUdpContext    m_pUdpCtx;
    SslConnetion*    m_pSslCon;

    function<void(UdpSocket*)> m_fSllInitDone;

    bool             m_bCloseReq;
    string           m_strDestAddr;

//    static mutex     s_mxSslInfo;
};

#endif  // #ifndef SSLSOCKET
