/* Copyright (C) 2016-2019 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
*/

#ifndef WITHOUT_OPENSSL

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
void OutputDebugStringA(const char* pOut)
{   // mkfifo /tmp/dbgout  ->  tail -f /tmp/dbgout
    int fdPipe = open("/tmp/dbgout", O_WRONLY | O_NONBLOCK);
    if (fdPipe >= 0)
    {
        std::string strTmp(pOut);
        write(fdPipe, strTmp.c_str(), strTmp.size());
        close(fdPipe);
    }
}
#endif

SslTcpSocketImpl::SslTcpSocketImpl(BaseSocket* pBkref) : TcpSocketImpl(pBkref), m_pSslCon(nullptr), m_bCloseReq(false), m_iSslInit(0)
{
    m_fnSslEncode = bind(&SslTcpSocketImpl::DatenEncode, this, _1, _2);
    m_fnSslDecode = bind(&SslTcpSocketImpl::DatenDecode, this, _1, _2);
}

SslTcpSocketImpl::SslTcpSocketImpl(BaseSocket* pBkref, TcpSocketImpl* pTcpSocket) : TcpSocketImpl(pBkref, pTcpSocket), m_pSslCon(nullptr), m_bCloseReq(false), m_iSslInit(0)
{
    m_fnSslEncode = bind(&SslTcpSocketImpl::DatenEncode, this, _1, _2);
    m_fnSslDecode = bind(&SslTcpSocketImpl::DatenDecode, this, _1, _2);
}

SslTcpSocketImpl::SslTcpSocketImpl(SslConnetion* pSslCon, const SOCKET fSock, const TcpServer* pRefServSocket) : TcpSocketImpl(fSock, pRefServSocket), m_pSslCon(pSslCon), m_bCloseReq(false), m_iSslInit(0)
{
    m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocketImpl::Close, this)));
    m_pSslCon->SetUserData(0, reinterpret_cast<void*>(&SslTcpSocketImpl::fnFoarwarder));
    m_pSslCon->SetUserData(1, this);
    m_fnSslEncode = bind(&SslTcpSocketImpl::DatenEncode, this, _1, _2);
    m_fnSslDecode = bind(&SslTcpSocketImpl::DatenDecode, this, _1, _2);

    SSL_set_accept_state((*m_pSslCon)());
}

SslTcpSocketImpl::~SslTcpSocketImpl()
{
    if (m_iSslInit == 1 && m_pSslCon->GetShutDownFlag() < 1)
        SSL_set_shutdown((*m_pSslCon)(), SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

    if (m_pSslCon != nullptr)
        delete m_pSslCon;
}

bool SslTcpSocketImpl::AddServerCertificat(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey, const char* szDhParamFileName)
{
    m_pServerCtx.emplace_back(SslServerContext());
    if (m_pServerCtx.back().SetCertificates(szCAcertificate, szHostCertificate, szHostKey) > 0)
    {
        if (m_pServerCtx.back().SetDhParamFile(szDhParamFileName) == true)
        {
            m_pServerCtx.back().AddVirtualHost(&m_pServerCtx);
            return true;
        }
    }

    m_pServerCtx.pop_back();
    return false;
}

bool SslTcpSocketImpl::AddCertificat(const char* const szHostCertificate, const char* const szHostKey)
{
    return (m_pClientCtx.SetCertificates(szHostCertificate, szHostKey) < 0) ? false : true;
}

bool SslTcpSocketImpl::SetCipher(const char* const szCipher)
{
    return m_pServerCtx.back().SetCipher(szCipher);
}

bool SslTcpSocketImpl::SetAcceptState()
{
    if (m_pSslCon != nullptr)
        delete m_pSslCon;

    m_pSslCon = new SslConnetion(m_pServerCtx.front());
    m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocketImpl::Close, this)));
    m_pSslCon->SetUserData(0, reinterpret_cast<void*>(&SslTcpSocketImpl::fnFoarwarder));
    m_pSslCon->SetUserData(1, this);

    SSL_set_accept_state((*m_pSslCon)());

    m_mxInDeque.lock();
    while (m_quInData.size() != 0)
    {
        DATA data = move(m_quInData.front());
        m_quInData.pop_front();

        uint32_t nToCopy = BUFLEN(data);
        m_atInBytes -= nToCopy;
        DatenDecode(reinterpret_cast<char*>(BUFFER(data).get()), nToCopy);
    }
    m_mxInDeque.unlock();

    return true;
}

bool SslTcpSocketImpl::Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint/* = AF_UNSPEC*/)
{
    m_pSslCon = new SslConnetion(m_pClientCtx);
    m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocketImpl::Close, this)));
    m_pSslCon->SetUserData(0, reinterpret_cast<void*>(&SslTcpSocketImpl::fnFoarwarder));
    m_pSslCon->SetUserData(1, this);
    
    m_pSslCon->SetSniName(szIpToWhere);

    if (m_vProtoList.size() > 0)
        m_pSslCon->SetAlpnProtokollNames(m_vProtoList);
    if (m_strTrustRootCert.size() > 0)
        m_pSslCon->SetTrustedRootCertificates(m_strTrustRootCert.c_str());

    TcpSocketImpl::BindFuncConEstablished(bind(&SslTcpSocketImpl::ConEstablished, this, _1));
    return TcpSocketImpl::Connect(szIpToWhere, sPort, AddrHint);
}

int SslTcpSocketImpl::DatenEncode(const void* buf, uint32_t nAnzahl)
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
                {
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
        OutputDebugString(wstring(L"SSL not initialized: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
    }

    return 0;
}

void SslTcpSocketImpl::Close() noexcept
{
    //OutputDebugString(L"SslTcpSocketImpl::Close\r\n");
    m_bCloseReq = true;

    if (GetErrorNo() == 0)  // We get here not because of an error
    {
        if (m_pSslCon != nullptr && SSL_get_shutdown((*m_pSslCon)()) < SSL_SENT_SHUTDOWN)
        {
            unique_lock<mutex> lock(m_mxOutDeque);
            bool bNewData = false;

            uint32_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
            while (nOutDataSize > 0)
            {
                OutputDebugString(wstring(L"SslGetOutDataSize unexpected full: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
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

            if (m_iSslInit == 1)
            {
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
            }

            lock.unlock();

            if (bNewData == true)
                TriggerWriteThread();
        }
    }

    TcpSocketImpl::Close();
}

function<void(TcpSocket*)> SslTcpSocketImpl::BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted) noexcept
{
    m_fClientConneted.swap(fClientConneted);
    return fClientConneted;
}

void SslTcpSocketImpl::ConEstablished(const TcpSocketImpl* const pTcpSocket)
{
    SSL_set_connect_state((*m_pSslCon)());

    m_iSslInit = SSL_do_handshake((*m_pSslCon)());
    if (m_iSslInit <= 0)
    {
        int iError = SSL_get_error((*m_pSslCon)(), m_iSslInit);
        if (iError != SSL_ERROR_WANT_READ)
        {
            m_iError = 0x80000000 | iError;
            m_iErrLoc = 15;
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

int SslTcpSocketImpl::DatenDecode(const char* buffer, uint32_t nAnzahl)
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

    m_iSslInit = SSL_is_init_finished((*m_pSslCon)());
    if (m_iSslInit == 0)
    {
        m_iSslInit = SSL_do_handshake((*m_pSslCon)());

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

        if (m_iSslInit <= 0)
        {
            int iError = SSL_get_error((*m_pSslCon)(), m_iSslInit);
            if (iError != SSL_ERROR_WANT_READ)
            {
                m_iError = 0x80000000 | iError;
                m_iErrLoc = 14;
                OutputDebugString(wstring(L"SSL_error: " + to_wstring(iError) + L", after SSL_do_handshake returnd: " + to_wstring(m_iSslInit) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)()))).c_str());
                OutputDebugStringA(string(", msg: " + m_pSslCon->GetSslErrAsString()).c_str());
                if (m_fError)
                    m_fError(m_pBkRef);
                return -1;
            }
        }
        else
        {
            //int iEarlyData = SSL_get_early_data_status((*m_pSslCon)());
            //if (iEarlyData != SSL_EARLY_DATA_NOT_SENT)
            //    OutputDebugString(wstring(L"SSL_get_early_data_status: " + to_wstring(iEarlyData) + L"\r\n").c_str());

            if (m_fClientConneted)
                m_fClientConneted(reinterpret_cast<SslTcpSocket*>(m_pBkRef));
        }
    }

    int iReturn = -1;
    if (m_iSslInit == 1)
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
            iReturn = 1;

            len = m_pSslCon->SslRead(Buffer.get(), 0x0000ffff, &iErrorHint); // get receive data from the SSL layer, and put it into the unencrypted receive Que
        }

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

void SslTcpSocketImpl::SetAlpnProtokollNames(vector<string>& vProtoList)
{
    m_vProtoList = vProtoList;
}

const string SslTcpSocketImpl::GetSelAlpnProtocol() const
{
    if (m_pSslCon != nullptr)
        return m_pSslCon->GetSelAlpnProtocol();
    return string();
}

void SslTcpSocketImpl::SetTrustedRootCertificates(const char* const szTrustRootCert)
{
    m_strTrustRootCert = szTrustRootCert;
}

long SslTcpSocketImpl::CheckServerCertificate(const char* const szHostName)
{
    if (m_pSslCon != nullptr)
        return m_pSslCon->CheckServerCertificate(szHostName);
    return -1;
}

//************************************************************************************

SslTcpServerImpl::SslTcpServerImpl(BaseSocket* pBkref) : TcpServerImpl(pBkref)
{
}

SslTcpSocket* const SslTcpServerImpl::MakeClientConnection(const SOCKET& fSock)
{
    if (m_SslCtx.size() == 0)
        m_SslCtx.emplace_back(SslServerContext());
    auto pImpl = new SslTcpSocketImpl(new SslConnetion(m_SslCtx.front()), fSock, reinterpret_cast<SslTcpServer*>(this->m_pBkRef));
    try
    {
        pImpl->SetSocketOption(fSock);
        pImpl->GetConnectionInfo();
    }

    catch (int iErrNo)
    {
        pImpl->SetErrorNo(iErrNo);
    }
    auto pTcpSock = new SslTcpSocket(pImpl);
    pImpl->m_pBkRef = pTcpSock;

    return pTcpSock;
}

bool SslTcpServerImpl::AddCertificat(const char* const szCAcertificate, const char* const szHostCertificate, const char* const szHostKey)
{
    m_SslCtx.emplace_back(SslServerContext());
    int iRet = m_SslCtx.back().SetCertificates(szCAcertificate, szHostCertificate, szHostKey);
    if (iRet != 1)
    {
        OutputDebugString(wstring(L"Certification could not be loaded, error: " + to_wstring(iRet) + L"\r\n").c_str());
        m_SslCtx.pop_back();
        return false;
    }
    m_SslCtx.back().AddVirtualHost(&m_SslCtx);
    return true;
}

bool SslTcpServerImpl::SetDHParameter(const char* const szDhParamFileName)
{
    if (m_SslCtx.size() == 0)
        return false;
    bool bRet = m_SslCtx.back().SetDhParamFile(szDhParamFileName);
    if (bRet == false)
    {
        OutputDebugString(wstring(L"DH File could not be loaded\r\n").c_str());
        m_SslCtx.pop_back();
    }
    return bRet;
}

bool SslTcpServerImpl::SetCipher(const char* const szCipher)
{
    if (m_SslCtx.size() == 0)
        return false;
    return m_SslCtx.back().SetCipher(szCipher);
}

void SslTcpServerImpl::SetAlpnProtokollNames(vector<string>& vStrProtoNames)
{
    for (auto& ctx : m_SslCtx)
        ctx.SetAlpnProtokollNames(vStrProtoNames);
}

//************************************************************************************

SslUdpSocketImpl::SslUdpSocketImpl(BaseSocket* pBkRef) : UdpSocketImpl(pBkRef), m_pSslCon(nullptr), m_bCloseReq(false)
{
    m_fnSslEncode = bind(&SslUdpSocketImpl::DatenEncode, this, _1, _2, _3);
    m_fnSslDecode = bind(&SslUdpSocketImpl::DatenDecode, this, _1, _2, _3);
}

SslUdpSocketImpl::~SslUdpSocketImpl()
{
    if (m_pSslCon != nullptr)
        delete m_pSslCon;
}

bool SslUdpSocketImpl::AddCertificat(const char* const szHostCertificate, const char* const szHostKey)
{
    m_pUdpCtx.SetCertificates(szHostCertificate, szHostKey);
    return true;
}

bool SslUdpSocketImpl::CreateServerSide(const char* const szIpToWhere, const uint16_t sPort, const char* const szIpToBind/* = nullptr*/)
{
    bool bRet = UdpSocketImpl::Create(szIpToWhere, sPort, szIpToBind);
    if (bRet == true)
    {
        m_pSslCon = new SslConnetion(m_pUdpCtx);
        m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocketImpl::Close, this)));

        //SSL_set_info_callback((*m_pSslCon)(), ssl_info_callbackServer);

        SSL_set_accept_state((*m_pSslCon)());
    }
    return bRet;
}

bool SslUdpSocketImpl::CreateClientSide(const char* const szIpToWhere, const uint16_t sPort, const char* const szDestAddr, const char* const szIpToBind/* = nullptr*/)
{
    m_strDestAddr = szDestAddr;
    bool bRet = UdpSocketImpl::Create(szIpToWhere, sPort, szIpToBind);
    if (bRet == true)
    {
        m_pSslCon = new SslConnetion(m_pUdpCtx);
        m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocketImpl::Close, this)));

        //SSL_set_info_callback((*m_pSslCon)(), ssl_info_callbackClient);

        SSL_set_connect_state((*m_pSslCon)());

        int iSslInit = SSL_do_handshake((*m_pSslCon)());
        if (iSslInit <= 0)
        {
            int iError = SSL_get_error((*m_pSslCon)(), iSslInit);
            if (iError != SSL_ERROR_WANT_READ)
            {
                m_iError = 0x80000000 | iError;
                m_iErrLoc = 15;
                OutputDebugString(wstring(L"SSL_error after SSL_Handshake: " + to_wstring(iError) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
                Close();
                return false;
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
                m_quOutData.emplace_back(temp, static_cast<uint32_t>(len), m_strDestAddr);
                bNewData = true;
            }
            nOutDataSize = m_pSslCon->SslGetOutDataSize();
        }

        lock.unlock();

        if (bNewData == true)
            TriggerWriteThread();

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
mutex SslUdpSocketImpl::s_mxSslInfo;

void SslUdpSocketImpl::ssl_info_callbackServer(const SSL* ssl, int where, int ret)
{
    if (ret == 0)
    {
        OutputDebugString(L"-- krx_ssl_info_callback: error occurred.\r\n");
        return;
    }

    const char* szName = "+ server";
    lock_guard<mutex> lock(SslUdpSocketImpl::s_mxSslInfo);
    SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
    SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START");
    SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}

void SslUdpSocketImpl::ssl_info_callbackClient(const SSL* ssl, int where, int ret)
{
    if (ret == 0)
    {
        OutputDebugString(L"-- krx_ssl_info_callback: error occurred.\r\n");
        return;
    }

    const char* szName = "+ client";
    lock_guard<mutex> lock(SslUdpSocketImpl::s_mxSslInfo);
    SSL_WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
    SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_START, "HANDSHAKE START");
    SSL_WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}
*/
int SslUdpSocketImpl::DatenEncode(const void* buf, uint32_t nAnzahl, const string& strAddress)
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
                {
                    m_atOutBytes += static_cast<uint32_t>(len);
                    m_quOutData.emplace_back(temp, static_cast<uint32_t>(len), strAddress);
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
                m_quOutData.emplace_back(temp, static_cast<uint32_t>(len), strAddress);
            }
            nOutDataSize = m_pSslCon->SslGetOutDataSize();
        }
        return nWritten;
    }
    else
    {
        OutputDebugString(wstring(L"SSL not initialized: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
    }

    return 0;
}

void SslUdpSocketImpl::Close() noexcept
{
    //OutputDebugString(L"SslTcpSocketImpl::Close\r\n");
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
                OutputDebugString(wstring(L"SslGetOutDataSize unexpected full: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
                auto temp = shared_ptr<uint8_t>(new uint8_t[nOutDataSize]);
                int32_t len = m_pSslCon->SslGetOutData(temp.get(), nOutDataSize);
                // Schreibt Daten in die SOCKET
                if (len > 0)
                {
                    m_atOutBytes += static_cast<uint32_t>(len);
                    m_quOutData.emplace_back(temp, static_cast<uint32_t>(len), m_strDestAddr);
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
                    m_quOutData.emplace_back(temp, static_cast<uint32_t>(len), m_strDestAddr);
                    bNewData = true;
                }
                nOutDataSize = m_pSslCon->SslGetOutDataSize();
            }

            lock.unlock();

            if (bNewData == true)
                TriggerWriteThread();
        }
    }

    UdpSocketImpl::Close();
}

function<void(UdpSocket*)> SslUdpSocketImpl::BindFuncSslInitDone(function<void(UdpSocket*)> fSllInitDone) noexcept
{
    m_fSllInitDone.swap(fSllInitDone);
    return fSllInitDone;
}

int SslUdpSocketImpl::DatenDecode(const char* buffer, uint32_t nAnzahl, const string& strAddress)
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
                m_quOutData.emplace_back(temp, static_cast<uint32_t>(len), strAddress);
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
                m_iError = 0x80000000 | iError;
                m_iErrLoc = 14;
                OutputDebugString(wstring(L"SSL_error: " + to_wstring(iError) + L", after SSL_do_handshake returned: " + to_wstring(iSslInit) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)()))).c_str());
                OutputDebugStringA(string(", msg: " + m_pSslCon->GetSslErrAsString()).c_str());
                if (m_fError && m_bStop == false)
                    m_fError(m_pBkRef);
                return -1;
            }
        }
        else
        {
            if (m_fSllInitDone != nullptr)
                m_fSllInitDone(reinterpret_cast<UdpSocket*>(m_pBkRef));
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
            m_quInData.emplace_back(tmp, len, strAddress);
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
                m_quOutData.emplace_back(temp, static_cast<uint32_t>(len), strAddress);
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
        return DatenDecode(buffer + nPut, nAnzahl - nPut, strAddress);
    }

    return iReturn;
}

#endif // WITHOUT_OPENSSL
