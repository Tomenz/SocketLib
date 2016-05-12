
#ifndef SSLSOCKET
#define SSLSOCKET

#include "SslSocket.h"

using namespace std::placeholders;

SslTcpSocket::SslTcpSocket(/*SslConnetion* pSslCon*/) : m_pSslCon(nullptr/*pSslCon*/), m_bShutDownReceive(false), m_bStopThread(false), m_bCloseReq(false), m_iShutDown(0), bHelper1(false), bHelper3(false)
{
    atomic_init(&m_atTmpBytes, static_cast<uint32_t>(0));
	atomic_init(&m_atInBytes, static_cast<uint32_t>(0));
	atomic_init(&m_atOutBytes, static_cast<uint32_t>(0));

    //pSslCon->SetErrorCb(bind(&BaseSocket::Close, this));
    TcpSocket::BindFuncBytesRecived(bind(&SslTcpSocket::DatenEmpfangen, this, _1));
    TcpSocket::BindCloseFunction(bind(&SslTcpSocket::Closeing, this, _1));

	//SSL_set_accept_state((*pSslCon)());
    //SSL_set_connect_state((*pSslCon)());

    //m_thPumpSsl = thread(&SslTcpSocket::PumpThread, this);
}

SslTcpSocket::SslTcpSocket(SslConnetion* pSslCon, SOCKINFO SockInfo) : m_pSslCon(pSslCon), TcpSocket(SockInfo), m_bShutDownReceive(false), m_bStopThread(false), m_bCloseReq(false), m_iShutDown(0), bHelper1(false), bHelper3(false)
{
    atomic_init(&m_atTmpBytes, static_cast<uint32_t>(0));
    atomic_init(&m_atInBytes, static_cast<uint32_t>(0));
    atomic_init(&m_atOutBytes, static_cast<uint32_t>(0));

    m_pSslCon->SetErrorCb(bind(&BaseSocket::Close, this));
    TcpSocket::BindFuncBytesRecived(bind(&SslTcpSocket::DatenEmpfangen, this, _1));
    TcpSocket::BindCloseFunction(bind(&SslTcpSocket::Closeing, this, _1));

    SSL_set_accept_state((*m_pSslCon)());

    m_thPumpSsl = thread(&SslTcpSocket::PumpThread, this);
}

SslTcpSocket::~SslTcpSocket()
{
    m_bStopThread = true;
    if (m_thPumpSsl.joinable() == true)
        m_thPumpSsl.join();

    if (m_fCloseing != nullptr)
        m_fCloseing(this);
}

bool SslTcpSocket::Connect(const char* const szIpToWhere, short sPort)
{
    m_pSslCon = new SslConnetion(SslClientContext());
    m_pSslCon->SetErrorCb(bind(&BaseSocket::Close, this));
    if (m_vProtoList.size() > 0)
        m_pSslCon->SetAlpnProtokollNames(m_vProtoList);
    if (m_strTrustRootCert.size() > 0)
        m_pSslCon->SetTrustedRootCertificates(m_strTrustRootCert.c_str());
    SSL_set_connect_state((*m_pSslCon)());

    TcpSocket::BindFuncConEstablished(bind(&SslTcpSocket::ConEstablished, this, _1));
    return TcpSocket::Connect(szIpToWhere, sPort);
}

uint32_t SslTcpSocket::Read(void* buf, uint32_t len)
{
    if (m_atInBytes == 0)
        return 0;

    size_t nOffset = 0;
    uint32_t nRet = 0;

    NextFromQue:
    m_mxInDeque.lock();
    DATA data = move(m_quInData.front());
    m_quInData.pop_front();
    m_mxInDeque.unlock();

    // Copy the data into the destination buffer
    size_t nToCopy = min(BUFLEN(data), len);
    copy(BUFFER(data).get(), BUFFER(data).get() + nToCopy, static_cast<char*>(buf) + nOffset);
    m_atInBytes -= nToCopy;
    nRet += nToCopy;

    if (nToCopy < BUFLEN(data))
    {   // Put the Rest of the Data back to the Que
        size_t nRest = BUFLEN(data) - nToCopy;
        shared_ptr<uint8_t> tmp(new uint8_t[nRest]);
        copy(BUFFER(data).get() + nToCopy, BUFFER(data).get() + nToCopy + nRest, tmp.get());
        m_mxInDeque.lock();
        m_quInData.emplace_front(tmp, nRest);
        m_mxInDeque.unlock();
        m_atInBytes += nRest;
    }
    else if (m_quInData.size() > 0 && len > nToCopy)
    {
        len -= nToCopy;
        nOffset += nToCopy;
        goto NextFromQue;
    }

    return nRet;
}

uint32_t SslTcpSocket::Write(const void* buf, uint32_t len)
{
    if (m_bStop == true || len == 0 || m_bCloseReq == true)
        return 0;

    shared_ptr<uint8_t> tmp(new uint8_t[len]);
    copy(static_cast<const char*>(buf), static_cast<const char*>(buf) + len, tmp.get());
    m_mxOutDeque.lock();
    m_quOutData.emplace_back(tmp, len);
    m_atOutBytes += len;
    m_mxOutDeque.unlock();

    return len;
}

void SslTcpSocket::Close()
{
    m_bCloseReq = true;
}

uint32_t SslTcpSocket::GetBytesAvailible()
{
    return m_atInBytes;
}

void SslTcpSocket::BindFuncBytesRecived(function<void(TcpSocket*)> fBytesRecived)
{
    m_fBytesRecived = fBytesRecived;
}

void SslTcpSocket::BindCloseFunction(function<void(BaseSocket*)> fCloseing)
{
    m_fCloseing = fCloseing;
}

void SslTcpSocket::BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted)
{
    m_fClientConneted = fClientConneted;
}

void SslTcpSocket::ConEstablished(TcpSocket* pTcpSocket)
{
    m_thPumpSsl = thread(&SslTcpSocket::PumpThread, this);
}

void SslTcpSocket::DatenEmpfangen(TcpSocket* pTcpSocket)
{
    uint32_t nAvalible = TcpSocket::GetBytesAvailible();

    if (nAvalible == 0)
    {
        m_bShutDownReceive = true;
        return;
    }

    shared_ptr<uint8_t> spBuffer(new uint8_t[nAvalible]);

    uint32_t nRead = TcpSocket::Read(spBuffer.get(), nAvalible);

    if (nRead > 0)
    {
        lock_guard<mutex> lock(m_mxTmpDeque);
        m_quTmpData.emplace_back(spBuffer, nRead);
        m_atTmpBytes += nRead;
    }
}

void SslTcpSocket::Closeing(BaseSocket* pTcpSocket)
{
    if (m_pSslCon != nullptr)
        delete m_pSslCon;
}

void SslTcpSocket::SetAlpnProtokollNames(vector<string> vProtoList)
{
    m_vProtoList = vProtoList;
}

string SslTcpSocket::GetSelAlpnProtocol()
{
    if (m_pSslCon != nullptr)
        return m_pSslCon->GetSelAlpnProtocol();
    return string();
}

void SslTcpSocket::SetTrustedRootCertificates(const char* szTrustRootCert)
{
    m_strTrustRootCert = szTrustRootCert;
}

long SslTcpSocket::CheckServerCertificate(const char* szHostName)
{
    if (m_pSslCon != nullptr)
        return m_pSslCon->CheckServerCertificate(szHostName);
    return -1;
}

void SslTcpSocket::PumpThread()
{
    atomic<bool> m_afReadCall;
    atomic_init(&m_afReadCall, false);
    uint64_t nTotalReceived = 0;
    bool bHandShakeOk = false;

    while (m_bStopThread == false)
    {
        bool bDidSomeWork = false;

        if (bHandShakeOk == false && m_pSslCon->HandShakeComplet() == true)
        {
            bHandShakeOk = true;
            if (m_fClientConneted != nullptr)
                m_fClientConneted(this);
        }

        if (m_pSslCon->GetShutDownFlag() != 1 && m_atTmpBytes > 0)
        {
            lock_guard<mutex> lock(m_mxTmpDeque);
            DATA data = move(m_quTmpData.front());
            m_quTmpData.pop_front();
            m_atTmpBytes -= BUFLEN(data);

            uint32_t nPut = m_pSslCon->SslPutInData(BUFFER(data).get(), BUFLEN(data));
            if (nPut != BUFLEN(data))
            {
                size_t nRest = BUFLEN(data) - nPut;
                shared_ptr<uint8_t> tmp(new uint8_t[nRest]);
                copy(BUFFER(data).get() + nPut, BUFFER(data).get() + nPut + nRest, tmp.get());
                m_quTmpData.emplace_front(tmp, nRest);
                m_atTmpBytes += nRest;
            }

            bDidSomeWork = true;
        }

        // The encrypted data the socket received are written to the SSL layer in the DatenEmpfangen function
        // 1. we read from the SSL layer the unencrypted bytes we received and put them into the Que, the application can get them
        // we notify the application that we have data to get

        if (bHandShakeOk == true && m_pSslCon->GetShutDownFlag() == INT32_MAX)
        {
            uint8_t Buffer[0x0000ffff];
            int32_t len = m_pSslCon->SslRead(Buffer, sizeof(Buffer)); // get receive data from the SSL layer, and put it into the unencrypted receive Que
            if (len > 0)
            {
                shared_ptr<uint8_t> tmp(new uint8_t[len]);
                copy(Buffer, Buffer + len, tmp.get());
                lock_guard<mutex> lock(m_mxInDeque);
                m_quInData.emplace_back(tmp, len);
                m_atInBytes += len;
                nTotalReceived += len;

                if (m_fBytesRecived != 0)
                {
                    bool bTemp = false;
                    if (atomic_compare_exchange_strong(&m_afReadCall, &bTemp, true) == true)
                    {
                        thread([&]() {
                            uint64_t nCountIn;
                            bool bSaveShutDown = m_bShutDownReceive;
                            do
                            {
                                nCountIn = nTotalReceived;
                                if (m_atInBytes > 0)
                                    m_fBytesRecived(this);
                            } while (nTotalReceived > nCountIn);

                            if (bSaveShutDown != m_bShutDownReceive)
                                m_fBytesRecived(this);

                            atomic_exchange(&m_afReadCall, false);
                        }).detach();
                    }

                    //if (m_bShutDownReceive == true)
                    //    break;
                }
                bDidSomeWork = true;
            }
        }

        // The next to blocks send data,
        // 1. we read the Que with unencrypted data and write it into the SSL layer
        // 2. we get the encrypted data from the SSL layer and write them to the base socket

        // We send the SSL layer as much data until the bio has less the 65535 bytes in the out Que
        if (m_pSslCon->GetShutDownFlag() == INT32_MAX && bHandShakeOk == true/*m_pSslCon->HandShakeComplet() == true*/ && m_atOutBytes > 0 && m_pSslCon->SslGetOutDataSize() < 0xffff)
        {
            m_mxOutDeque.lock();
            DATA data = move(m_quOutData.front());
            m_quOutData.pop_front();
            m_mxOutDeque.unlock();
            m_atOutBytes -= BUFLEN(data);

            size_t nWritten = m_pSslCon->SslWrite(BUFFER(data).get(), BUFLEN(data));
            if (nWritten != BUFLEN(data))
            {
                size_t nRest = BUFLEN(data) - nWritten;

                shared_ptr<uint8_t> tmp(new uint8_t[nRest]);
                copy(BUFFER(data).get() + nWritten, BUFFER(data).get() + nWritten + nRest, tmp.get());
                m_mxOutDeque.lock();
                m_quOutData.emplace_front(tmp, nRest);
                m_atOutBytes += nRest;
                m_mxOutDeque.unlock();
            }
            bDidSomeWork = true;
        }

        // Get the out Que of the openssl bio, the buffer is already encrypted
        uint32_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
        if (nOutDataSize > 0)
        {
            auto temp = shared_ptr<uint8_t>(new uint8_t[nOutDataSize]);
            int32_t len = m_pSslCon->SslGetOutData(temp.get(), nOutDataSize);
            // Schreibt Daten in die SOCKET
            if (len > 0)
                TcpSocket::Write(temp.get(), len);

            bDidSomeWork = true;
        }

        // we close the ssl connection
        if (m_bCloseReq == true && m_iShutDown == 0 && m_pSslCon->SslGetOutDataSize() == 0 && m_atOutBytes == 0)
        {
            m_iShutDown = m_pSslCon->ShutDownConnection();
            if (m_iShutDown == 1 || m_iShutDown == -1)
            {
                bHelper3 = true;
                TcpSocket::Close();
            }
        }

        if (m_bCloseReq == true && m_iShutDown == 1 && bHelper3 == false)
        {
            bHelper3 = true;
            TcpSocket::Close();
        }

        if (bDidSomeWork == false)
            this_thread::sleep_for(chrono::milliseconds(1));
    }

    while (m_afReadCall == true)
        this_thread::sleep_for(chrono::milliseconds(1));

    /* thread-local cleanup */
    ERR_remove_thread_state(nullptr);

    bHelper1 = true;
}

//************************************************************************************

SslTcpServer::SslTcpServer()
{
    TcpServer::BindNewConnection(bind(&SslTcpServer::NeueVerbindungen, this, _1, _2));
}

SslTcpServer::~SslTcpServer()
{
}

void SslTcpServer::BindNewConnection(function<void(SslTcpServer*, int)> fNewConnetion)
{
    m_fNewConnection = fNewConnetion;
}

void SslTcpServer::NeueVerbindungen(TcpServer* pTcpServer, int nCountNewConnections)
{
    m_fNewConnection(this, nCountNewConnections);
}

SslTcpSocket* SslTcpServer::GetNextPendingConnection()
{
    SOCKINFO SockInfo;
    {
        lock_guard<mutex> lock(m_mtAcceptList);
        if (m_vSockAccept.size() == 0)
            return nullptr;
        SockInfo = *begin(m_vSockAccept);
        m_vSockAccept.erase(begin(m_vSockAccept));
    }

    return new SslTcpSocket(new SslConnetion(*m_SslCtx.begin()->get()), SockInfo);
}

bool SslTcpServer::AddCertificat(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey)
{
    m_SslCtx.emplace_back(make_shared<SslServerContext>());
    m_SslCtx.back()->SetCertificates(szCAcertificate, szHostCertificate, szHostKey);
    return true;
}

#endif
