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

#include <vector>

#include "StdSocket.h"
#include "OpenSSLWraper.h"

using namespace OpenSSLWrapper;

class SslTcpServer;

class SslTcpSocket : public TcpSocket
{
public:
    explicit SslTcpSocket(/*SslConnetion* pSslCon*/);
    explicit SslTcpSocket(TcpSocket* pTcpSocket);
    virtual ~SslTcpSocket();
    bool AddServerCertificat(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey, const char* szDhParamFileName);
    bool SetAcceptState();
    bool Connect(const char* const szIpToWhere, const uint16_t sPort) override;
    uint32_t Read(void* buf, uint32_t len) override;
    size_t Write(const void* buf, size_t len) override;
    void Close() noexcept override;
    uint32_t GetBytesAvailible() const noexcept override;
    function<void(TcpSocket*)> BindFuncBytesRecived(function<void(TcpSocket*)> fBytesRecived) noexcept override;
    function<void(BaseSocket*)> BindCloseFunction(function<void(BaseSocket*)> fCloseing) noexcept override;
    function<void(TcpSocket*)> BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted) noexcept override;
    bool IsSslConnection() const noexcept override { return true; }

    void SetAlpnProtokollNames(vector<string>& vProtoList);
    const string GetSelAlpnProtocol() const;
    void SetTrustedRootCertificates(const char* const szTrustRootCert);
    long CheckServerCertificate(const char* const szHostName);

#pragma message("TODO!!! Folge Zeile wieder entfernen.")
    static atomic<uint32_t> s_atAnzahlPumps;

private:
    friend SslTcpServer;
    explicit SslTcpSocket(SslConnetion* pSslCon, const SOCKET fSock, const TcpServer* pRefServSocket);
    void ConEstablished(const TcpSocket* const pTcpSocket);
	void DatenEmpfangen(const TcpSocket* const pTcpSocket);
    void Closeing(const BaseSocket* const pTcpSocket);
    void PumpThread();

    static const string& fnFoarwarder(void* obj) { return static_cast<SslTcpSocket*>(obj)->GetInterfaceAddr(); }

private:
    SslClientContext m_pClientCtx;
    vector<SslServerContext>  m_pServerCtx;
    SslConnetion*    m_pSslCon;
    function<void(TcpSocket*)> m_fBytesRecived;
    function<void(BaseSocket*)> m_fCloseing;
    function<void(TcpSocket*)> m_fClientConneted;
    thread           m_thPumpSsl;

    mutex            m_mxTmpDeque;
    deque<DATA>      m_quTmpData;
    atomic<uint32_t> m_atTmpBytes;

    mutex            m_mxInDeque;
    deque<DATA>      m_quInData;
    atomic<uint32_t> m_atInBytes;
    mutex            m_mxOutDeque;
    deque<DATA>      m_quOutData;
    atomic<uint32_t> m_atOutBytes;

    int              m_iShutDownReceive;
    bool             m_bStopThread;
    bool             m_bCloseReq;
    int              m_iShutDown;

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
    uint32_t Read(void* buf, uint32_t len, string& strFrom) override;
    size_t Write(const void* buf, size_t len, const string& strTo) override;
    void Close() noexcept override;
    uint32_t GetBytesAvailible() const noexcept override;
    function<void(BaseSocket*)> BindCloseFunction(function<void(BaseSocket*)> fCloseing) noexcept override;
    function<void(UdpSocket*)> BindFuncBytesRecived(function<void(UdpSocket*)> fBytesRecived) noexcept override;

private:
    void DatenEmpfangen(const UdpSocket* const pUdpSocket);
    void Closeing(const BaseSocket* const pTcpSocket);
    void PumpThread();

//    static void ssl_info_callbackServer(const SSL* ssl, int where, int ret);
//    static void ssl_info_callbackClient(const SSL* ssl, int where, int ret);

private:
    SslUdpContext    m_pUdpCtx;
    SslConnetion*    m_pSslCon;

    function<void(UdpSocket*)> m_fBytesRecived;
    function<void(BaseSocket*)> m_fCloseing;
    thread           m_thPumpSsl;

    mutex            m_mxTmpDeque;
    deque<DATA>      m_quTmpData;
    atomic<uint32_t> m_atTmpBytes;

    mutex            m_mxInDeque;
    deque<DATA>      m_quInData;
    atomic<uint32_t> m_atInBytes;
    mutex            m_mxOutDeque;
    deque<DATA>      m_quOutData;
    atomic<uint32_t> m_atOutBytes;

    bool             m_bStopThread;
    bool             m_bCloseReq;
    string           m_strDestAddr;

//    static mutex     s_mxSslInfo;
};
