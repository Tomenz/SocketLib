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
#include <functional>
#include <string>

#include "SslSocket.h"

using namespace std::placeholders;

#if !defined (_WIN32) && !defined (_WIN64)
#include <locale>
#include <iomanip>
#include <codecvt>
#include <fcntl.h>
#include <unistd.h>
void OutputDebugString(const wchar_t* pOut)
{   // mkfifo /tmp/dbgout  ->  tail -f /tmp/dbgout
    int fdPipe = open("/tmp/dbgout", O_WRONLY | O_NONBLOCK);
    if (fdPipe >= 0)
    {
        wstring strTmp(pOut);
        write(fdPipe, wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t>().to_bytes(strTmp).c_str(), strTmp.size());
        close(fdPipe);
    }
}
extern void OutputDebugStringA(const char* pOut);
#endif

SslTcpSocket::SslTcpSocket() : m_pSslCon(nullptr), m_iShutDownReceive(false), /*m_bStopThread(false),*/ m_bCloseReq(false), m_iShutDown(0)
{
    m_fnSslEncode = bind(&SslTcpSocket::DatenEncode, this, _1, _2);
    m_fnSslDecode = bind(&SslTcpSocket::DatenDecode, this, _1, _2);
}

SslTcpSocket::SslTcpSocket(TcpSocket* pTcpSocket) : TcpSocket(pTcpSocket), m_pSslCon(nullptr), m_iShutDownReceive(false), /*m_bStopThread(false),*/ m_bCloseReq(false), m_iShutDown(0)
{
    m_fnSslEncode = bind(&SslTcpSocket::DatenEncode, this, _1, _2);
    m_fnSslDecode = bind(&SslTcpSocket::DatenDecode, this, _1, _2);
}

SslTcpSocket::SslTcpSocket(SslConnetion* pSslCon, const SOCKET fSock, const TcpServer* pRefServSocket) : TcpSocket(fSock, pRefServSocket), m_pSslCon(pSslCon), m_iShutDownReceive(false), /*m_bStopThread(false),*/ m_bCloseReq(false), m_iShutDown(0)
{
    m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocket::Close, this)));
    m_pSslCon->SetUserData(0, reinterpret_cast<void*>(&SslTcpSocket::fnFoarwarder));
    m_pSslCon->SetUserData(1, this);
    m_fnSslEncode = bind(&SslTcpSocket::DatenEncode, this, _1, _2);
    m_fnSslDecode = bind(&SslTcpSocket::DatenDecode, this, _1, _2);

    SSL_set_accept_state((*m_pSslCon)());
}

SslTcpSocket::~SslTcpSocket()
{
    if (m_pSslCon != nullptr)
        delete m_pSslCon;
}

bool SslTcpSocket::AddServerCertificat(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey, const char* szDhParamFileName)
{
    m_pServerCtx.emplace_back(SslServerContext());
    m_pServerCtx.back().SetCertificates(szCAcertificate, szHostCertificate, szHostKey);
    m_pServerCtx.back().SetDhParamFile(szDhParamFileName);

    m_pServerCtx.back().AddVirtualHost(&m_pServerCtx);

    return true;
}

bool SslTcpSocket::SetAcceptState()
{
    if (m_pSslCon != nullptr)
        delete m_pSslCon;

    m_pSslCon = new SslConnetion(m_pServerCtx.front());

    SSL_set_accept_state((*m_pSslCon)());

    return true;
}

bool SslTcpSocket::Connect(const char* const szIpToWhere, const uint16_t sPort)
{
    m_pSslCon = new SslConnetion(m_pClientCtx);
    m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocket::Close, this)));
    m_pSslCon->SetUserData(0, reinterpret_cast<void*>(&SslTcpSocket::fnFoarwarder));
    m_pSslCon->SetUserData(1, this);

    if (m_vProtoList.size() > 0)
        m_pSslCon->SetAlpnProtokollNames(m_vProtoList);
    if (m_strTrustRootCert.size() > 0)
        m_pSslCon->SetTrustedRootCertificates(m_strTrustRootCert.c_str());

    TcpSocket::BindFuncConEstablished(bind(&SslTcpSocket::ConEstablished, this, _1));
    return TcpSocket::Connect(szIpToWhere, sPort);
}

int SslTcpSocket::DatenEncode(const void* buf, uint32_t nAnzahl)
{
    if (m_bCloseReq == true)
        return -1;
    if (SSL_get_shutdown((*m_pSslCon)()) >= SSL_SENT_SHUTDOWN)
        return -1;

    unique_lock<mutex> lock(m_mxOutDeque);
    //OutputDebugString(wstring(L"Bytes written soll: " + to_wstring(len) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
    int iSslInit = SSL_is_init_finished((*m_pSslCon)());
    if (iSslInit == 1)
    {
        int iErrorHint = 0;
        uint32_t nWritten = m_pSslCon->SslWrite(static_cast<const uint8_t*>(buf), nAnzahl, &iErrorHint);
        while (nWritten != nAnzahl && (iErrorHint == SSL_ERROR_WANT_READ || iErrorHint == SSL_ERROR_WANT_WRITE))
        {
OutputDebugString(wstring(L"Bytes written part: " + to_wstring(nWritten) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
            // Get the out Que of the openssl bio, the buffer is already encrypted
            uint32_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
            while (nOutDataSize > 0)
            {
                auto temp = shared_ptr<uint8_t>(new uint8_t[nOutDataSize]);
                int32_t len = m_pSslCon->SslGetOutData(temp.get(), nOutDataSize);
                // Schreibt Daten in die SOCKET
                //OutputDebugString(wstring(L"    SSL Bytes written: " + to_wstring(len) + L"\r\n").c_str());
                if (len > 0)
                {   //TcpSocket::Write(temp.get(), len);
                    m_atOutBytes += static_cast<uint32_t>(len);
                    m_quOutData.emplace_back(temp, static_cast<uint32_t>(len));
                }

                nOutDataSize = m_pSslCon->SslGetOutDataSize();
            }
            nWritten += m_pSslCon->SslWrite(static_cast<const uint8_t*>(buf) + nWritten, nAnzahl - nWritten, &iErrorHint);
        }
        //OutputDebugString(wstring(L"Bytes written ist : " + to_wstring(nWritten) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
        // Get the out Que of the openssl bio, the buffer is already encrypted
        uint32_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
        while (nOutDataSize > 0)
        {
            auto temp = shared_ptr<uint8_t>(new uint8_t[nOutDataSize]);
            int32_t len = m_pSslCon->SslGetOutData(temp.get(), nOutDataSize);
            // Schreibt Daten in die SOCKET
            if (len > 0)
            {
                m_atOutBytes += static_cast<uint32_t>(len);
                m_quOutData.emplace_back(temp, static_cast<uint32_t>(len));
            }
            nOutDataSize = m_pSslCon->SslGetOutDataSize();
        }
        return nWritten;
    }
    else
    {
        OutputDebugString(wstring(L"SSL not initalisiert: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
    }

    return 0;
}

void SslTcpSocket::Close() noexcept
{
    //OutputDebugString(L"SslTcpSocket::Close\r\n");
    m_bCloseReq = true;

    if (GetErrorNo() == 0)  // We get here not because of an error
    {
        if (SSL_get_shutdown((*m_pSslCon)()) < SSL_SENT_SHUTDOWN)
        {
            unique_lock<mutex> lock(m_mxOutDeque);
            bool bNewData = false;

            uint32_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
            while (nOutDataSize > 0)
            {
                OutputDebugString(wstring(L"SslGetOutDataSize unexpectet full: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
                auto temp = shared_ptr<uint8_t>(new uint8_t[nOutDataSize]);
                int32_t len = m_pSslCon->SslGetOutData(temp.get(), nOutDataSize);
                // Schreibt Daten in die SOCKET
                if (len > 0)
                {
                    m_atOutBytes += static_cast<uint32_t>(len);
                    m_quOutData.emplace_back(temp, static_cast<uint32_t>(len));
                    bNewData = true;
                }
                nOutDataSize = m_pSslCon->SslGetOutDataSize();
            }

            m_pSslCon->ShutDownConnection();
            // Get the out Que of the openssl bio, the buffer is already encrypted
            nOutDataSize = m_pSslCon->SslGetOutDataSize();
            while (nOutDataSize > 0)
            {
                auto temp = shared_ptr<uint8_t>(new uint8_t[nOutDataSize]);
                int32_t len = m_pSslCon->SslGetOutData(temp.get(), nOutDataSize);
                // Schreibt Daten in die SOCKET
                if (len > 0)
                {
                    m_atOutBytes += static_cast<uint32_t>(len);
                    m_quOutData.emplace_back(temp, static_cast<uint32_t>(len));
                    bNewData = true;
                }
                nOutDataSize = m_pSslCon->SslGetOutDataSize();
            }

            lock.unlock();

            if (bNewData == true)
                TriggerWriteThread();
        }
    }

    TcpSocket::Close();
}

function<void(TcpSocket*)> SslTcpSocket::BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted) noexcept
{
    m_fClientConneted.swap(fClientConneted);
    return fClientConneted;
}

void SslTcpSocket::ConEstablished(const TcpSocket* const pTcpSocket)
{
    SSL_set_connect_state((*m_pSslCon)());

    int iSslInit = SSL_do_handshake((*m_pSslCon)());
    if (iSslInit <= 0)
    {
        int iError = SSL_get_error((*m_pSslCon)(), iSslInit);
        if (iError != SSL_ERROR_WANT_READ)
        {
            OutputDebugString(wstring(L"SSL_error after SSL_Handshake: " + to_wstring(iError) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
            Close();
            return;
        }
    }

    unique_lock<mutex> lock(m_mxOutDeque);
    bool bNewData = false;

    uint32_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
    while (nOutDataSize > 0)
    {
        auto temp = shared_ptr<uint8_t>(new uint8_t[nOutDataSize]);
        int32_t len = m_pSslCon->SslGetOutData(temp.get(), nOutDataSize);
        // Schreibt Daten in die SOCKET
        if (len > 0)
        {
            m_atOutBytes += static_cast<uint32_t>(len);
            m_quOutData.emplace_back(temp, static_cast<uint32_t>(len));
            bNewData = true;
        }
        nOutDataSize = m_pSslCon->SslGetOutDataSize();
    }

    lock.unlock();

    if (bNewData == true)
        TriggerWriteThread();
}

int SslTcpSocket::DatenDecode(const char* buffer, uint32_t nAnzahl)
{
    if (buffer == nullptr || nAnzahl == 0)
        return 0;

    uint32_t nPut = m_pSslCon->SslPutInData(reinterpret_cast<uint8_t*>(const_cast<char*>(buffer)), nAnzahl);

    if (m_bCloseReq == true)
        return -1;

    if (SSL_get_shutdown((*m_pSslCon)()) >= SSL_RECEIVED_SHUTDOWN)
    {
        OutputDebugString(wstring(L"SSL_RECEIVED_SHUTDOWN on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
        m_pSslCon->ShutDownConnection();
        Close();
        return -1;
    }

    //if (SSL_renegotiate_pending((*m_pSslCon)()) == 1)
    //    OutputDebugString(wstring(L"SSL_renegotiate on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());

    int iSslInit = SSL_is_init_finished((*m_pSslCon)());
    if (iSslInit == 0)
    {
        iSslInit = SSL_do_handshake((*m_pSslCon)());

        unique_lock<mutex> lock(m_mxOutDeque);
        bool bNewData = false;

        // Get the out Que of the openssl bio, the buffer is already encrypted
        uint32_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
        while (nOutDataSize > 0)
        {
            auto temp = shared_ptr<uint8_t>(new uint8_t[nOutDataSize]);
            int32_t len = m_pSslCon->SslGetOutData(temp.get(), nOutDataSize);
            // Schreibt Daten in die SOCKET
            if (len > 0)
            {
                m_atOutBytes += static_cast<uint32_t>(len);
                m_quOutData.emplace_back(temp, static_cast<uint32_t>(len));
                bNewData = true;
            }
            nOutDataSize = m_pSslCon->SslGetOutDataSize();
        }

        lock.unlock();

        if (bNewData == true)
            TriggerWriteThread();

        if (iSslInit <= 0)
        {
            int iError = SSL_get_error((*m_pSslCon)(), iSslInit);
            if (iError != SSL_ERROR_WANT_READ)
            {
                OutputDebugString(wstring(L"SSL_error: " + to_wstring(iError) + L", after SSL_do_handshake returnd: " + to_wstring(iSslInit) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)()))).c_str());
                OutputDebugStringA(string(", msg: " + m_pSslCon->GetSslErrAsString()).c_str());
                Close();
                return -1;
            }
        }
        else
        {
            //int iEarlyData = SSL_get_early_data_status((*m_pSslCon)());
            //if (iEarlyData != SSL_EARLY_DATA_NOT_SENT)
            //    OutputDebugString(wstring(L"SSL_get_early_data_status: " + to_wstring(iEarlyData) + L"\r\n").c_str());

            if (m_fClientConneted)
                m_fClientConneted(this);
        }
    }

    int iReturn = -1;
    if (iSslInit == 1)
    {
        unique_ptr<uint8_t> Buffer(new uint8_t[0x0000ffff]);
        int iErrorHint = 0;
        int32_t len = m_pSslCon->SslRead(Buffer.get(), 0x0000ffff, &iErrorHint); // get receive data from the SSL layer, and put it into the unencrypted receive Que
        while (len > 0)
        {
            shared_ptr<uint8_t> tmp(new uint8_t[len]);
            copy(Buffer.get(), Buffer.get() + len, tmp.get());
            m_mxInDeque.lock();
            m_quInData.emplace_back(tmp, len);
            m_atInBytes += len;
            m_mxInDeque.unlock();

            len = m_pSslCon->SslRead(Buffer.get(), 0x0000ffff, &iErrorHint); // get receive data from the SSL layer, and put it into the unencrypted receive Que
        }
        iReturn = 1;

        unique_lock<mutex> lock(m_mxOutDeque);
        bool bNewData = false;

        // Get the out Que of the openssl bio, the buffer is already encrypted
        uint32_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
        while (nOutDataSize > 0)
        {
            auto temp = shared_ptr<uint8_t>(new uint8_t[nOutDataSize]);
            int32_t len = m_pSslCon->SslGetOutData(temp.get(), nOutDataSize);
            // Schreibt Daten in die SOCKET
            if (len > 0)
            {
                m_atOutBytes += static_cast<uint32_t>(len);
                m_quOutData.emplace_back(temp, static_cast<uint32_t>(len));
                bNewData = true;
            }
            nOutDataSize = m_pSslCon->SslGetOutDataSize();
        }

        lock.unlock();

        if (bNewData == true)
            TriggerWriteThread();

        //if (SSL_renegotiate_pending((*m_pSslCon)()) == 1)
        //    OutputDebugString(wstring(L"SSL_renegotiate on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
    }

    if (nPut != 0 && nPut != nAnzahl)
    {
        OutputDebugString(wstring(L"SslPutInData konnte nicht alles fassen on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
        return DatenDecode(buffer + nPut, nAnzahl - nPut);
    }

    return iReturn;
}

void SslTcpSocket::SetAlpnProtokollNames(vector<string>& vProtoList)
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

//************************************************************************************

SslTcpSocket* const SslTcpServer::MakeClientConnection(const SOCKET& fSock)
{
    return new SslTcpSocket(new SslConnetion(m_SslCtx.front()), fSock, this);
}

bool SslTcpServer::AddCertificat(const char* const szCAcertificate, const char* const szHostCertificate, const char* const szHostKey)
{
    m_SslCtx.emplace_back(SslServerContext());
    m_SslCtx.back().SetCertificates(szCAcertificate, szHostCertificate, szHostKey);

    m_SslCtx.back().AddVirtualHost(&m_SslCtx);
    return true;
}

bool SslTcpServer::SetDHParameter(const char* const szDhParamFileName)
{
    return m_SslCtx.back().SetDhParamFile(szDhParamFileName);
}

bool SslTcpServer::SetCipher(const char* const szCipher)
{
    return m_SslCtx.back().SetCipher(szCipher);
}

//************************************************************************************

SslUdpSocket::SslUdpSocket() : m_bStopThread(false), m_bCloseReq(false)
{
    atomic_init(&m_atTmpBytes, static_cast<uint32_t>(0));
    atomic_init(&m_atInBytes, static_cast<uint32_t>(0));
    atomic_init(&m_atOutBytes, static_cast<uint32_t>(0));

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
    m_pUdpCtx.SetCertificates(szHostCertificate, szHostKey);
    return true;
}

bool SslUdpSocket::CreateServerSide(const char* const szIpToWhere, const short sPort, const char* const szIpToBind/* = nullptr*/)
{
    bool bRet = UdpSocket::Create(szIpToWhere, sPort, szIpToBind);
    if (bRet == true)
    {
        m_pSslCon = new SslConnetion(m_pUdpCtx);
        m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocket::Close, this)));

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
        m_pSslCon = new SslConnetion(m_pUdpCtx);
        m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocket::Close, this)));

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

void SslUdpSocket::Close() noexcept
{
    //OutputDebugString(L"SslTcpSocket::Close\r\n");
    m_bCloseReq = true;
}

uint32_t SslUdpSocket::GetBytesAvailible() const noexcept
{
    return m_atInBytes;
}

function<void(UdpSocket*)> SslUdpSocket::BindFuncBytesRecived(function<void(UdpSocket*)> fBytesRecived) noexcept
{
    m_fBytesRecived.swap(fBytesRecived);
    return fBytesRecived;
}

function<void(BaseSocket*)> SslUdpSocket::BindCloseFunction(function<void(BaseSocket*)> fCloseing) noexcept
{
    m_fCloseing.swap(fCloseing);
    return fCloseing;
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
    if (m_fCloseing)
        m_fCloseing(this);
}

void SslUdpSocket::PumpThread()
{
    atomic<bool> m_afReadCall;
    atomic_init(&m_afReadCall, false);
    mutex mxNotify;
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
                m_mxInDeque.unlock();

                if (m_fBytesRecived)
                {
                    lock_guard<mutex> lock(mxNotify);
                    if (m_afReadCall == false)
                    {
                        atomic_exchange(&m_afReadCall, true);

                        thread([&]()
                        {
//                            if (bShutDownReceive == true && m_atInBytes == 0)  // If we start the thread, with no bytes in the Que, but the Shutdown is marked, we execute the callback below the loop
//                                bShutDownReceive = false;

                            mxNotify.lock();
                            while (m_atInBytes > 0)
                            {
                                mxNotify.unlock();
                                m_fBytesRecived(this);
                                mxNotify.lock();
                            }

                            atomic_exchange(&m_afReadCall, false);
                            mxNotify.unlock();
                        }).detach();
                    }

                    //if (m_bShutDownReceive == true)
                    //    break;
                }
                bDidSomeWork = true;
            }
            else if (m_atTmpBytes == 0 && m_atInBytes == 0 && m_afReadCall == false && m_fBytesRecived)
                m_fBytesRecived(this);
        }
        else if (bHandShakeOk == false && m_fBytesRecived)
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
