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

#ifndef SSLSOCKET
#define SSLSOCKET

#include "SslSocket.h"

using namespace std::placeholders;

#pragma message("TODO!!! Folge Zeile wieder entfernen.")
atomic<uint32_t> SslTcpSocket::s_atAnzahlPumps(0);

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

SslTcpSocket::SslTcpSocket(SslConnetion* pSslCon, const SOCKET fSock) : TcpSocket(fSock), m_pSslCon(pSslCon), m_bShutDownReceive(false), m_bStopThread(false), m_bCloseReq(false), m_iShutDown(0), bHelper1(false), bHelper3(false)
{
    atomic_init(&m_atTmpBytes, static_cast<uint32_t>(0));
    atomic_init(&m_atInBytes, static_cast<uint32_t>(0));
    atomic_init(&m_atOutBytes, static_cast<uint32_t>(0));

    m_pSslCon->SetErrorCb(bind(&BaseSocket::Close, this));
    TcpSocket::BindFuncBytesRecived(bind(&SslTcpSocket::DatenEmpfangen, this, _1));
    TcpSocket::BindCloseFunction(bind(&SslTcpSocket::Closeing, this, _1));

    if (m_iError != 0)
        return;

    SSL_set_accept_state((*m_pSslCon)());

    m_thPumpSsl = thread(&SslTcpSocket::PumpThread, this);
}

SslTcpSocket::~SslTcpSocket()
{
    //OutputDebugString(L"SslTcpSocket::~SslTcpSocket\r\n");
    m_bStopThread = true;
    if (m_thPumpSsl.joinable() == true)
        m_thPumpSsl.join();

    if (m_pSslCon != nullptr)
        delete m_pSslCon;

    //if (m_fCloseing != nullptr)
    //    m_fCloseing(this);
}

bool SslTcpSocket::Connect(const char* const szIpToWhere, const short sPort)
{
    m_pClientCtx = make_shared<SslClientContext>();
    m_pSslCon = new SslConnetion(m_pClientCtx.get());
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

    uint32_t nOffset = 0;
    uint32_t nRet = 0;

    NextFromQue:
    m_mxInDeque.lock();
    DATA data = move(m_quInData.front());
    m_quInData.pop_front();
    m_mxInDeque.unlock();

    // Copy the data into the destination buffer
    uint32_t nToCopy = min(BUFLEN(data), len);
    copy(BUFFER(data).get(), BUFFER(data).get() + nToCopy, static_cast<uint8_t*>(buf) + nOffset);
    m_atInBytes -= nToCopy;
    nRet += nToCopy;

    if (nToCopy < BUFLEN(data))
    {   // Put the Rest of the Data back to the Que
        uint32_t nRest = BUFLEN(data) - nToCopy;
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

size_t SslTcpSocket::Write(const void* buf, size_t len)
{
    if (m_bStop == true || len == 0 || m_bCloseReq == true)
        return 0;

    shared_ptr<uint8_t> tmp(new uint8_t[len]);
    copy(static_cast<const uint8_t*>(buf), static_cast<const uint8_t*>(buf) + len, tmp.get());
    m_mxOutDeque.lock();
    m_quOutData.emplace_back(tmp, static_cast<uint32_t>(len));
    m_atOutBytes += static_cast<uint32_t>(len);
    m_mxOutDeque.unlock();

    return len;
}

void SslTcpSocket::Close()
{
    //OutputDebugString(L"SslTcpSocket::Close\r\n");
    m_bCloseReq = true;
}

uint32_t SslTcpSocket::GetBytesAvailible() const
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

void SslTcpSocket::ConEstablished(const TcpSocket* const pTcpSocket)
{
    m_thPumpSsl = thread(&SslTcpSocket::PumpThread, this);
}

void SslTcpSocket::DatenEmpfangen(const TcpSocket* const pTcpSocket)
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

void SslTcpSocket::Closeing(const BaseSocket* const pTcpSocket)
{
    //OutputDebugString(L"SslTcpSocket::Closeing\r\n");
    if (m_fCloseing != nullptr)
        m_fCloseing(this);

//    if (m_pSslCon != nullptr)
//        delete m_pSslCon;
}

void SslTcpSocket::SetAlpnProtokollNames(vector<string> vProtoList)
{
    m_vProtoList = vProtoList;
}

const string SslTcpSocket::GetSelAlpnProtocol() const
{
    if (m_pSslCon != nullptr)
        return m_pSslCon->GetSelAlpnProtocol();
    return string();
}

void SslTcpSocket::SetTrustedRootCertificates(const char* const szTrustRootCert)
{
    m_strTrustRootCert = szTrustRootCert;
}

long SslTcpSocket::CheckServerCertificate(const char* const szHostName)
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
#pragma message("TODO!!! Folge Zeile wieder entfernen.")
    s_atAnzahlPumps++;

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
            m_mxTmpDeque.lock();
            DATA data = move(m_quTmpData.front());
            m_quTmpData.pop_front();
            m_atTmpBytes -= BUFLEN(data);
            m_mxTmpDeque.unlock();

            uint32_t nPut = m_pSslCon->SslPutInData(BUFFER(data).get(), BUFLEN(data));
            if (nPut != BUFLEN(data))
            {
                uint32_t nRest = BUFLEN(data) - nPut;
                shared_ptr<uint8_t> tmp(new uint8_t[nRest]);
                copy(BUFFER(data).get() + nPut, BUFFER(data).get() + nPut + nRest, tmp.get());
                lock_guard<mutex> lock(m_mxTmpDeque);
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
                m_mxInDeque.lock();
                m_quInData.emplace_back(tmp, len);
                m_atInBytes += len;
                nTotalReceived += len;
                m_mxInDeque.unlock();

                if (m_fBytesRecived != 0)
                {
                    lock_guard<mutex> lock(m_mxNotify);
                    if (m_afReadCall == false)
                    {
                        atomic_exchange(&m_afReadCall, true);

                        thread([&](bool bShutDownReceive) {
                            uint64_t nCountIn;

                            if (bShutDownReceive == true && m_atInBytes == 0)  // If we start the thread, with no bytes in the Que, but the Shutdown is marked, we execute the callback below the loop
                                bShutDownReceive = false;

                            do
                            {
                                nCountIn = nTotalReceived;
                                if (m_atInBytes > 0)
                                    m_fBytesRecived(this);
                            } while (nTotalReceived > nCountIn || m_atInBytes > 0);

                            m_mxNotify.lock();
                            if (bShutDownReceive != m_bShutDownReceive)
                            {
                                m_mxNotify.unlock();
                                m_fBytesRecived(this), bHelper1 = true;
                                m_mxNotify.lock();
                            }

                            atomic_exchange(&m_afReadCall, false);
                            m_mxNotify.unlock();
                        }, m_bShutDownReceive).detach();
                    }

                    //if (m_bShutDownReceive == true)
                    //    break;
                }
                bDidSomeWork = true;
            }
            else if (m_bShutDownReceive == true && m_atTmpBytes == 0 && m_atInBytes == 0 && m_afReadCall == false && m_fBytesRecived != nullptr)
                m_fBytesRecived(this);
        }
        else if (bHandShakeOk == false && m_bShutDownReceive == true && m_fBytesRecived != nullptr)
            m_fBytesRecived(this);

        // The next to blocks send data,
        // 1. we read the Que with unencrypted data and write it into the SSL layer
        // 2. we get the encrypted data from the SSL layer and write them to the base socket

        // We send the SSL layer as much data until the bio has less the 65535 bytes in the out Que
        if (m_pSslCon->GetShutDownFlag() == INT32_MAX && bHandShakeOk == true/*m_pSslCon->HandShakeComplet() == true*/ && m_atOutBytes > 0 && m_pSslCon->SslGetOutDataSize() < 0xffff)
        {
            m_mxOutDeque.lock();
            DATA data = move(m_quOutData.front());
            m_quOutData.pop_front();
            m_atOutBytes -= BUFLEN(data);
            m_mxOutDeque.unlock();

            uint32_t nWritten = m_pSslCon->SslWrite(BUFFER(data).get(), BUFLEN(data));
            if (nWritten != BUFLEN(data))
            {
                uint32_t nRest = BUFLEN(data) - nWritten;

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
        if (m_bCloseReq == true && m_iShutDown == 0 && m_pSslCon->SslGetOutDataSize() == 0 && (m_atOutBytes == 0 || m_pSslCon->GetShutDownFlag() != INT32_MAX))
        {
            m_iShutDown = m_pSslCon->ShutDownConnection();
            if (m_iShutDown == 1 || m_iShutDown == -1 || (m_iShutDown == 0 && bHandShakeOk == false))
            {
                bHelper3 = true;
                break;
            }
        }

        if (bDidSomeWork == false)
            this_thread::sleep_for(chrono::milliseconds(1));
    }

    while (m_afReadCall == true)
        this_thread::sleep_for(chrono::milliseconds(1));
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /* thread-local cleanup */
    ERR_remove_thread_state(nullptr);
#endif
    TcpSocket::Close();

#pragma message("TODO!!! Folge Zeile wieder entfernen.")
    s_atAnzahlPumps--;
}

//************************************************************************************

SslTcpServer::SslTcpServer()
{
}

SslTcpServer::~SslTcpServer()
{
}

SslTcpSocket* const SslTcpServer::MakeClientConnection(const SOCKET& fSock)
{
    return new SslTcpSocket(new SslConnetion(m_SslCtx.begin()->get()), fSock);
}

bool SslTcpServer::AddCertificat(const char* const szCAcertificate, const char* const szHostCertificate, const char* const szHostKey)
{
    m_SslCtx.emplace_back(make_shared<SslServerContext>());
    m_SslCtx.back()->SetCertificates(szCAcertificate, szHostCertificate, szHostKey);

    m_SslCtx.begin()->get()->AddVirtualHost(&m_SslCtx);
    return true;
}

bool SslTcpServer::SetDHParameter(const char* const szDhParamFileName)
{
    return m_SslCtx.back()->SetDhParamFile(szDhParamFileName);
}

//************************************************************************************

SslUdpSocket::SslUdpSocket() : m_bStopThread(false), m_bCloseReq(false)
{
    atomic_init(&m_atTmpBytes, static_cast<uint32_t>(0));
    atomic_init(&m_atInBytes, static_cast<uint32_t>(0));
    atomic_init(&m_atOutBytes, static_cast<uint32_t>(0));

    m_pUdpCtx = make_shared<SslUdpContext>();

    UdpSocket::BindFuncBytesRecived(bind(&SslUdpSocket::DatenEmpfangen, this, _1));
    UdpSocket::BindCloseFunction(bind(&SslUdpSocket::Closeing, this, _1));
}

SslUdpSocket::~SslUdpSocket()
{
    m_bStopThread = true;
    if (m_thPumpSsl.joinable() == true)
        m_thPumpSsl.join();

    if (m_pSslCon != nullptr)
        delete m_pSslCon;
}

bool SslUdpSocket::AddCertificat(const char* const szHostCertificate, const char* const szHostKey)
{
    m_pUdpCtx.get()->SetCertificates(szHostCertificate, szHostKey);
    return true;
}

bool SslUdpSocket::CreateServerSide(const char* const szIpToWhere, const short sPort, const char* const szIpToBind/* = nullptr*/)
{
    bool bRet = UdpSocket::Create(szIpToWhere, sPort, szIpToBind);
    if (bRet == true)
    {
        m_pSslCon = new SslConnetion(m_pUdpCtx.get());
        m_pSslCon->SetErrorCb(bind(&BaseSocket::Close, this));

        //SSL_set_info_callback((*m_pSslCon)(), ssl_info_callbackServer);

        SSL_set_accept_state((*m_pSslCon)());
        m_thPumpSsl = thread(&SslUdpSocket::PumpThread, this);
    }
    return bRet;
}

bool SslUdpSocket::CreateClientSide(const char* const szIpToWhere, const short sPort, const char* const szDestAddr, const char* const szIpToBind/* = nullptr*/)
{
    m_strDestAddr = szDestAddr;
    bool bRet = UdpSocket::Create(szIpToWhere, sPort, szIpToBind);
    if (bRet == true)
    {
        m_pSslCon = new SslConnetion(m_pUdpCtx.get());
        m_pSslCon->SetErrorCb(bind(&BaseSocket::Close, this));

        //SSL_set_info_callback((*m_pSslCon)(), ssl_info_callbackClient);

        SSL_set_connect_state((*m_pSslCon)());
        m_thPumpSsl = thread(&SslUdpSocket::PumpThread, this);
        SSL_do_handshake((*m_pSslCon)());
    }
    return bRet;
}
/*
#define SSL_WHERE_INFO(ssl, w, flag, msg)                  \
{                                                          \
    if(w & flag)                                           \
    {                                                      \
      printf("%s: ", szName);                                \
      printf("%20.20s", msg);                              \
      printf(" - %30.30s ", SSL_state_string_long(ssl));   \
      printf(" - %5.10s ", SSL_state_string(ssl));         \
      printf("\n");                                        \
    }                                                      \
  }
mutex SslUdpSocket::s_mxSslInfo;

void SslUdpSocket::ssl_info_callbackServer(const SSL* ssl, int where, int ret)
{
    if (ret == 0)
    {
        OutputDebugString(L"-- krx_ssl_info_callback: error occured.\r\n");
        return;
    }

    const char* szName = "+ server";
    lock_guard<mutex> lock(SslUdpSocket::s_mxSslInfo);
    SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
    SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START");
    SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}

void SslUdpSocket::ssl_info_callbackClient(const SSL* ssl, int where, int ret)
{
    if (ret == 0)
    {
        OutputDebugString(L"-- krx_ssl_info_callback: error occured.\r\n");
        return;
    }

    const char* szName = "+ client";
    lock_guard<mutex> lock(SslUdpSocket::s_mxSslInfo);
    SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
    SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START");
    SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}
*/
uint32_t SslUdpSocket::Read(void* buf, uint32_t len, string& strFrom)
{
    if (m_atInBytes == 0)
        return 0;

    uint32_t nOffset = 0;
    uint32_t nRet = 0;

    m_mxInDeque.lock();
    DATA data = move(m_quInData.front());
    m_quInData.pop_front();
    m_mxInDeque.unlock();

    // Copy the data into the destination buffer
    uint32_t nToCopy = min(BUFLEN(data), len);
    copy(BUFFER(data).get(), BUFFER(data).get() + nToCopy, static_cast<uint8_t*>(buf) + nOffset);
    m_atInBytes -= nToCopy;
    strFrom = ADDRESS(data);
    nRet += nToCopy;

    if (nToCopy < BUFLEN(data))
    {   // Put the Rest of the Data back to the Que
        uint32_t nRest = BUFLEN(data) - nToCopy;
        shared_ptr<uint8_t> tmp(new uint8_t[nRest]);
        copy(BUFFER(data).get() + nToCopy, BUFFER(data).get() + nToCopy + nRest, tmp.get());
        m_mxInDeque.lock();
        m_quInData.emplace_front(tmp, nRest, strFrom);
        m_mxInDeque.unlock();
        m_atInBytes += nRest;
    }

    return nRet;
}

size_t SslUdpSocket::Write(const void* buf, size_t len, const string& strTo)
{
    if (m_bStop == true || len == 0 || m_bCloseReq == true)
        return 0;

    shared_ptr<uint8_t> tmp(new uint8_t[len]);
    copy(static_cast<const uint8_t*>(buf), static_cast<const uint8_t*>(buf) + len, tmp.get());
    m_mxOutDeque.lock();
    m_quOutData.emplace_back(tmp, static_cast<uint32_t>(len), strTo);
    m_atOutBytes += static_cast<uint32_t>(len);
    m_mxOutDeque.unlock();

    return len;
}

void SslUdpSocket::Close()
{
    //OutputDebugString(L"SslTcpSocket::Close\r\n");
    m_bCloseReq = true;
}

uint32_t SslUdpSocket::GetBytesAvailible() const
{
    return m_atInBytes;
}

void SslUdpSocket::BindFuncBytesRecived(function<void(UdpSocket*)> fBytesRecived)
{
    m_fBytesRecived = fBytesRecived;
}

void SslUdpSocket::BindCloseFunction(function<void(BaseSocket*)> fCloseing)
{
    m_fCloseing = fCloseing;
}

void SslUdpSocket::DatenEmpfangen(const UdpSocket* const pUdpSocket)
{
    uint32_t nAvalible = UdpSocket::GetBytesAvailible();

    if (nAvalible == 0)
        return;

    shared_ptr<uint8_t> spBuffer(new uint8_t[nAvalible]);

    string strFrom;
    uint32_t nRead = UdpSocket::Read(spBuffer.get(), nAvalible, strFrom);

    if (nRead > 0)
    {
        lock_guard<mutex> lock(m_mxTmpDeque);
        m_quTmpData.emplace_back(spBuffer, nRead, strFrom);
        m_atTmpBytes += nRead;
    }
}

void SslUdpSocket::Closeing(const BaseSocket* const pUdpSocket)
{
    //OutputDebugString(L"SslTcpSocket::Closeing\r\n");
    if (m_fCloseing != nullptr)
        m_fCloseing(this);
}
/*
void SslUdpSocket::PumpThread()
{
    atomic<bool> m_afReadCall;
    atomic_init(&m_afReadCall, false);
    uint64_t nTotalReceived = 0;
    bool bHandShakeOk = false;
    string strLastReadAddr(m_strDestAddr);
    string strLastSendAddr(m_strDestAddr);

    while (m_bStopThread == false)
    {
        bool bDidSomeWork = false;

        if (bHandShakeOk == false && m_pSslCon->HandShakeComplet() == true)
            bHandShakeOk = true;
        //else if (bHandShakeOk == false)
        //    SSL_do_handshake((*m_pSslCon)());

        if (m_pSslCon->GetShutDownFlag() != 1 && m_atTmpBytes > 0)
        {
            m_mxTmpDeque.lock();
            DATA data = move(m_quTmpData.front());
            m_quTmpData.pop_front();
            m_atTmpBytes -= BUFLEN(data);
            m_mxTmpDeque.unlock();
            strLastReadAddr = ADDRESS(data);

            uint32_t nPut = m_pSslCon->SslPutInData(BUFFER(data).get(), BUFLEN(data));
            if (nPut != BUFLEN(data))
            {
                uint32_t nRest = BUFLEN(data) - nPut;
                shared_ptr<uint8_t> tmp(new uint8_t[nRest]);
                copy(BUFFER(data).get() + nPut, BUFFER(data).get() + nPut + nRest, tmp.get());
                lock_guard<mutex> lock(m_mxTmpDeque);
                m_quTmpData.emplace_front(tmp, nRest, strLastReadAddr);
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
                m_mxInDeque.lock();
                m_quInData.emplace_back(tmp, len, strLastReadAddr);
                m_atInBytes += len;
                nTotalReceived += len;
                m_mxInDeque.unlock();

                if (m_fBytesRecived != 0)
                {
                    lock_guard<mutex> lock(m_mxNotify);
                    if (m_afReadCall == false)
                    {
                        atomic_exchange(&m_afReadCall, true);

                        thread([&]() {
                            uint64_t nCountIn;

//                            if (bShutDownReceive == true && m_atInBytes == 0)  // If we start the thread, with no bytes in the Que, but the Shutdown is marked, we execute the callback below the loop
//                                bShutDownReceive = false;

                            do
                            {
                                nCountIn = nTotalReceived;
                                if (m_atInBytes > 0)
                                    m_fBytesRecived(this);
                            } while (nTotalReceived > nCountIn || m_atInBytes > 0);

                            m_mxNotify.lock();
                            atomic_exchange(&m_afReadCall, false);
                            m_mxNotify.unlock();
                        }).detach();
                    }

                    //if (m_bShutDownReceive == true)
                    //    break;
                }
                bDidSomeWork = true;
            }
            else if (m_atTmpBytes == 0 && m_atInBytes == 0 && m_afReadCall == false && m_fBytesRecived != nullptr)
                m_fBytesRecived(this);
        }
        else if (bHandShakeOk == false && m_fBytesRecived != nullptr)
            m_fBytesRecived(this);

        // The next to blocks send data,
        // 1. we read the Que with unencrypted data and write it into the SSL layer
        // 2. we get the encrypted data from the SSL layer and write them to the base socket

        // We send the SSL layer as much data until the bio has less the 65535 bytes in the out Que
        if (m_pSslCon->GetShutDownFlag() == INT32_MAX && bHandShakeOk == true && m_atOutBytes > 0 && m_pSslCon->SslGetOutDataSize() < 0xffff)
        {
            m_mxOutDeque.lock();
            DATA data = move(m_quOutData.front());
            m_quOutData.pop_front();
            m_atOutBytes -= BUFLEN(data);
            strLastSendAddr = ADDRESS(data);
            m_mxOutDeque.unlock();

            uint32_t nWritten = m_pSslCon->SslWrite(BUFFER(data).get(), BUFLEN(data));
            if (nWritten != BUFLEN(data))
            {
                uint32_t nRest = BUFLEN(data) - nWritten;

                shared_ptr<uint8_t> tmp(new uint8_t[nRest]);
                copy(BUFFER(data).get() + nWritten, BUFFER(data).get() + nWritten + nRest, tmp.get());
                m_mxOutDeque.lock();
                m_quOutData.emplace_front(tmp, nRest, strLastSendAddr);
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
                UdpSocket::Write(temp.get(), len, strLastReadAddr);

            bDidSomeWork = true;
        }

        // we close the ssl connection
        if (m_bCloseReq == true && m_pSslCon->SslGetOutDataSize() == 0 && (m_atOutBytes == 0 || m_pSslCon->GetShutDownFlag() != INT32_MAX))
        {
//            m_iShutDown = m_pSslCon->ShutDownConnection();
//            if (m_iShutDown == 1 || m_iShutDown == -1 || (m_iShutDown == 0 && bHandShakeOk == false))
                break;
        }

        if (bDidSomeWork == false)
            this_thread::sleep_for(chrono::milliseconds(1));
    }

    while (m_afReadCall == true)
        this_thread::sleep_for(chrono::milliseconds(1));

    ERR_remove_thread_state(nullptr);

    UdpSocket::Close();

}
*/
void SslUdpSocket::PumpThread()
{
    atomic<bool> m_afReadCall;
    atomic_init(&m_afReadCall, false);
    uint64_t nTotalReceived = 0;
    bool bHandShakeOk = false;
    string strLastReadAddr(m_strDestAddr);
    string strLastSendAddr(m_strDestAddr);

    while (m_bStopThread == false)
    {
        bool bDidSomeWork = false;

        if (bHandShakeOk == false && SSL_is_init_finished((*m_pSslCon)()))
            bHandShakeOk = true;

        // Get the out Que of the openssl bio, the buffer is already encrypted
        uint32_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
        if (nOutDataSize > 0)
        {
            auto temp = shared_ptr<uint8_t>(new uint8_t[nOutDataSize]);
            int32_t len = m_pSslCon->SslGetOutData(temp.get(), nOutDataSize);
            // Schreibt Daten in die SOCKET
            if (len > 0)
                UdpSocket::Write(temp.get(), len, strLastReadAddr);

            bDidSomeWork = true;
        }

        if (m_atTmpBytes > 0)
        {
            m_mxTmpDeque.lock();
            DATA data = move(m_quTmpData.front());
            m_quTmpData.pop_front();
            m_atTmpBytes -= BUFLEN(data);
            m_mxTmpDeque.unlock();
            strLastReadAddr = ADDRESS(data);

            uint32_t nPut = m_pSslCon->SslPutInData(BUFFER(data).get(), BUFLEN(data));
            if (nPut != BUFLEN(data))
            {
                uint32_t nRest = BUFLEN(data) - nPut;
                shared_ptr<uint8_t> tmp(new uint8_t[nRest]);
                copy(BUFFER(data).get() + nPut, BUFFER(data).get() + nPut + nRest, tmp.get());
                lock_guard<mutex> lock(m_mxTmpDeque);
                m_quTmpData.emplace_front(tmp, nRest, strLastReadAddr);
                m_atTmpBytes += nRest;
            }

            if (nPut > 0 && bHandShakeOk == false)
            {
                if (!SSL_is_init_finished((*m_pSslCon)()))
                {
                    int iRet = SSL_do_handshake((*m_pSslCon)());
                    if (iRet <= 0)
                    {
                        int iRet2 = SSL_get_error((*m_pSslCon)(), iRet);
                        if (iRet2 <= 0)
                        {
//                            OutputDebugString(L"SSL Error\r\n");
                        }
                    }
                }
                else
                    bHandShakeOk = true;
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
                m_mxInDeque.lock();
                m_quInData.emplace_back(tmp, len, strLastReadAddr);
                m_atInBytes += len;
                nTotalReceived += len;
                m_mxInDeque.unlock();

                if (m_fBytesRecived != 0)
                {
                    lock_guard<mutex> lock(m_mxNotify);
                    if (m_afReadCall == false)
                    {
                        atomic_exchange(&m_afReadCall, true);

                        thread([&]() {
                            uint64_t nCountIn;

                            //                            if (bShutDownReceive == true && m_atInBytes == 0)  // If we start the thread, with no bytes in the Que, but the Shutdown is marked, we execute the callback below the loop
                            //                                bShutDownReceive = false;

                            do
                            {
                                nCountIn = nTotalReceived;
                                if (m_atInBytes > 0)
                                    m_fBytesRecived(this);
                            } while (nTotalReceived > nCountIn || m_atInBytes > 0);

                            m_mxNotify.lock();
                            atomic_exchange(&m_afReadCall, false);
                            m_mxNotify.unlock();
                        }).detach();
                    }

                    //if (m_bShutDownReceive == true)
                    //    break;
                }
                bDidSomeWork = true;
            }
            else if (m_atTmpBytes == 0 && m_atInBytes == 0 && m_afReadCall == false && m_fBytesRecived != nullptr)
                m_fBytesRecived(this);
        }
        else if (bHandShakeOk == false && m_fBytesRecived != nullptr)
            m_fBytesRecived(this);

        // The next to blocks send data,
        // 1. we read the Que with unencrypted data and write it into the SSL layer
        // 2. we get the encrypted data from the SSL layer and write them to the base socket

        // We send the SSL layer as much data until the bio has less the 65535 bytes in the out Que
        if (m_pSslCon->GetShutDownFlag() == INT32_MAX && bHandShakeOk == true && m_atOutBytes > 0 && m_pSslCon->SslGetOutDataSize() < 0xffff)
        {
            m_mxOutDeque.lock();
            DATA data = move(m_quOutData.front());
            m_quOutData.pop_front();
            m_atOutBytes -= BUFLEN(data);
            strLastSendAddr = ADDRESS(data);
            m_mxOutDeque.unlock();

            uint32_t nWritten = m_pSslCon->SslWrite(BUFFER(data).get(), BUFLEN(data));
            if (nWritten != BUFLEN(data))
            {
                uint32_t nRest = BUFLEN(data) - nWritten;

                shared_ptr<uint8_t> tmp(new uint8_t[nRest]);
                copy(BUFFER(data).get() + nWritten, BUFFER(data).get() + nWritten + nRest, tmp.get());
                m_mxOutDeque.lock();
                m_quOutData.emplace_front(tmp, nRest, strLastSendAddr);
                m_atOutBytes += nRest;
                m_mxOutDeque.unlock();
            }
            bDidSomeWork = true;
        }

        if (bDidSomeWork == false)
            this_thread::sleep_for(chrono::milliseconds(1));
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ERR_remove_thread_state(nullptr);
#endif
    UdpSocket::Close();
}

#endif
