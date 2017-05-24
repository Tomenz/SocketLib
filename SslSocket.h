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
	SslTcpSocket(/*SslConnetion* pSslCon*/);
    virtual ~SslTcpSocket();
    bool Connect(const char* const szIpToWhere, const short sPort);
    uint32_t Read(void* buf, uint32_t len) override;
    size_t Write(const void* buf, size_t len) override;
    void Close() override;
    uint32_t GetBytesAvailible() const override;
    void BindFuncBytesRecived(function<void(TcpSocket*)> fBytesRecived) override;
    void BindCloseFunction(function<void(BaseSocket*)> fCloseing) override;
    void BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted) override;
    bool IsSslConnection() const override { return true; }

    void SetAlpnProtokollNames(vector<string> vProtoList);
    const string GetSelAlpnProtocol() const;
    void SetTrustedRootCertificates(const char* const szTrustRootCert);
    long CheckServerCertificate(const char* const szHostName);

#pragma message("TODO!!! Folge Zeile wieder entfernen.")
    static atomic<uint32_t> s_atAnzahlPumps;

private:
    friend SslTcpServer;
    SslTcpSocket(SslConnetion* pSslCon, const SOCKET fSock, const TcpServer* pRefServSocket);
    void ConEstablished(const TcpSocket* const pTcpSocket);
	void DatenEmpfangen(const TcpSocket* const pTcpSocket);
    void Closeing(const BaseSocket* const pTcpSocket);
    void PumpThread();

private:
    shared_ptr<SslClientContext>  m_pClientCtx;
    SslConnetion*    m_pSslCon;
    function<void(SslTcpSocket*)> m_fBytesRecived;
    function<void(SslTcpSocket*)> m_fCloseing;
    function<void(SslTcpSocket*)> m_fClientConneted;
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

#pragma message("TODO!!! Folge Zeile wieder entfernen.")
    friend void sigusr1_handler(int);
    friend int main(int, const char*[]);
};

class SslTcpServer : public TcpServer
{
public:
    SslTcpSocket* const MakeClientConnection(const SOCKET&);
    bool AddCertificat(const char* const szCAcertificate, const char* const szHostCertificate, const char* const szHostKey);
    bool SetDHParameter(const char* const szDhParamFileName);

private:
    vector<shared_ptr<SslServerContext>> m_SslCtx;
};

class SslUdpSocket : public UdpSocket
{
public:
    SslUdpSocket();
    virtual ~SslUdpSocket();
    bool AddCertificat(const char* const szHostCertificate, const char* const szHostKey);
    bool CreateServerSide(const char* const szIpToWhere, const short sPort, const char* const szIpToBind = nullptr);
    bool CreateClientSide(const char* const szIpToWhere, const short sPort, const char* const szDestAddr, const char* const szIpToBind = nullptr);
    virtual uint32_t Read(void* buf, uint32_t len, string& strFrom);
    virtual size_t Write(const void* buf, size_t len, const string& strTo);
    virtual void Close();
    virtual uint32_t GetBytesAvailible() const;
    virtual void BindCloseFunction(function<void(BaseSocket*)> fCloseing);
    virtual void BindFuncBytesRecived(function<void(UdpSocket*)> fBytesRecived);

private:
    void DatenEmpfangen(const UdpSocket* const pUdpSocket);
    void Closeing(const BaseSocket* const pTcpSocket);
    void PumpThread();

//    static void ssl_info_callbackServer(const SSL* ssl, int where, int ret);
//    static void ssl_info_callbackClient(const SSL* ssl, int where, int ret);

private:
    shared_ptr<SslUdpContext>  m_pUdpCtx;
    SslConnetion*    m_pSslCon;

    function<void(SslUdpSocket*)> m_fBytesRecived;
    function<void(SslUdpSocket*)> m_fCloseing;
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
