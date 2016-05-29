#pragma once

#include <vector>

#include "StdSocket.h"
#include "OpenSSLWraper.h"

using namespace OpenSSLWrapper;

class SslTcpServer;

class SslTcpSocket : public TcpSocket
{
    friend SslTcpServer;
public:
	SslTcpSocket(/*SslConnetion* pSslCon*/);
    virtual ~SslTcpSocket();
    bool Connect(const char* const szIpToWhere, short sPort);
    uint32_t Read(void* buf, uint32_t len) override;
    uint32_t Write(const void* buf, uint32_t len) override;
    void Close() override;
    uint32_t GetBytesAvailible() override;
    void BindFuncBytesRecived(function<void(TcpSocket*)> fBytesRecived) override;
    void BindCloseFunction(function<void(BaseSocket*)> fCloseing) override;
    void BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted) override;
    bool IsSslConnection() override { return true; }

    void SetAlpnProtokollNames(vector<string> vProtoList);
    string GetSelAlpnProtocol();
    void SetTrustedRootCertificates(const char* szTrustRootCert);
    long CheckServerCertificate(const char* szHostName);

private:
	SslTcpSocket(SslConnetion* pSslCon, SOCKET fSock);
    void ConEstablished(TcpSocket* pTcpSocket);
	void DatenEmpfangen(TcpSocket* pTcpSocket);
    void Closeing(BaseSocket* pTcpSocket);
    void PumpThread();

private:
    shared_ptr<SslClientContext>  m_pClientCtx;
    SslConnetion*    m_pSslCon;
    function<void(SslTcpSocket*)> m_fBytesRecived;
    function<void(SslTcpSocket*)> m_fCloseing;
    function<void(SslTcpSocket*)> m_fClientConneted;
    thread           m_thPumpSsl;
    mutex            m_mxSsl;

    mutex            m_mxTmpDeque;
    deque<DATA>      m_quTmpData;
    atomic<uint32_t> m_atTmpBytes;

    mutex            m_mxInDeque;
    deque<DATA>      m_quInData;
    atomic<uint32_t> m_atInBytes;
    mutex            m_mxOutDeque;
    deque<DATA>      m_quOutData;
    atomic<uint32_t> m_atOutBytes;

    bool             m_bShutDownReceive;
    bool             m_bStopThread;
    bool             m_bCloseReq;
    int              m_iShutDown;

    vector<string>   m_vProtoList;
    string           m_strTrustRootCert;

    bool bHelper1;
    bool bHelper3;
};

class SslTcpServer : public TcpServer
{
public:
    SslTcpServer();
    virtual ~SslTcpServer();
    void BindNewConnection(function<void(SslTcpServer*, int)> fNewConnetion);
    SslTcpSocket* GetNextPendingConnection() override;
    bool AddCertificat(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey);

private:
    void NeueVerbindungen(TcpServer* pTcpServer, int nCountNewConnections);

private:
    function<void(SslTcpServer*, int)> m_fNewConnection;
    vector<shared_ptr<SslServerContext>> m_SslCtx;
};

