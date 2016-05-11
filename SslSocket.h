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
	SslTcpSocket(SslConnetion* pSslCon);
    virtual ~SslTcpSocket();
    uint32_t Read(void* buf, uint32_t len) override;
    uint32_t Write(const void* buf, uint32_t len) override;
    void Close() override;
    uint32_t GetBytesAvailible() override;
    void BindFuncBytesRecived(function<void(TcpSocket*)> fBytesRecived) override;
    void BindCloseFunction(function<void(BaseSocket*)> fCloseing) override;
    bool IsSslConnection() override { return true; }

private:
	SslTcpSocket(SslConnetion* pSslCon, SOCKINFO SockInfo);
	void DatenEmpfangen(TcpSocket* pTcpSocket);
    void Closeing(BaseSocket* pTcpSocket);
    void PumpThread();

private:
    SslConnetion*    m_pSslCon;
    function<void(SslTcpSocket*)> m_fBytesRecived;
    function<void(SslTcpSocket*)> m_fCloseing;
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

