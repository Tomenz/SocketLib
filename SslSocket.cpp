/* Copyright (C) 2016-2020 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
*/

#ifndef WITHOUT_OPENSSL

#include <string>
#include <algorithm>

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

SslTcpSocketImpl::SslTcpSocketImpl(BaseSocket* pBkref) : TcpSocketImpl(pBkref), m_bCloseReq(false), m_iSslInit(0)
{
    m_fnSslInitDone = [this]() noexcept -> int { return m_iSslInit; };
    m_fnSslEncode = bind(&SslTcpSocketImpl::DatenEncode, this, _1, _2);
    m_fnSslDecode = bind(&SslTcpSocketImpl::DatenDecode, this, _1, _2, _3);
}

SslTcpSocketImpl::SslTcpSocketImpl(BaseSocket* pBkref, TcpSocketImpl* pTcpSocket) : TcpSocketImpl(pBkref, pTcpSocket), m_bCloseReq(false), m_iSslInit(0)
{   // Switch from Tcp to Ssl/Tls
    m_fnSslInitDone = [this]() noexcept -> int { return m_iSslInit; };
    m_fnSslEncode = bind(&SslTcpSocketImpl::DatenEncode, this, _1, _2);
    m_fnSslDecode = bind(&SslTcpSocketImpl::DatenDecode, this, _1, _2, _3);

    m_fClientConnected.swap(TcpSocketImpl::m_fClientConnected);
    m_fClientConnectedParam.swap(TcpSocketImpl::m_fClientConnectedParam);
}

SslTcpSocketImpl::~SslTcpSocketImpl()
{
    if (m_iSslInit == 1 && m_pSslCon->GetShutDownFlag() < 1)
        m_pSslCon->SSLSetShutdown(SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
}

bool SslTcpSocketImpl::AddServerCertificate(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey, const char* szDhParamFileName)
{
    m_pServerCtx.emplace_back(SslServerContext());
    if (m_pServerCtx.back().SetCertificates(szCAcertificate, szHostCertificate, szHostKey) > 0)
    {
        if (szDhParamFileName == nullptr || m_pServerCtx.back().SetDhParamFile(szDhParamFileName) == true)
        {
            m_pServerCtx.back().AddVirtualHost(&m_pServerCtx);
            return true;
        }
    }

    m_pServerCtx.pop_back();
    return false;
}

bool SslTcpSocketImpl::AddCertificate(const char* const szHostCertificate, const char* const szHostKey)
{
    return (m_pClientCtx.SetCertificates(szHostCertificate, szHostKey) < 0) ? false : true;
}

bool SslTcpSocketImpl::SetCipher(const char* const szCipher) noexcept
{
    return m_pServerCtx.back().SetCipher(szCipher);
}

bool SslTcpSocketImpl::SetAcceptState()
{
    if (m_pServerCtx.size() == 0)
        return false;

    m_pSslCon = make_unique<SslConnection>(m_pServerCtx.front());
    m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocketImpl::Close, this)));
    m_pSslCon->SetUserData(0, reinterpret_cast<void*>(&SslTcpSocketImpl::fnForwarder));
    m_pSslCon->SetUserData(1, this);

    m_pSslCon->SSLSetAcceptState();

    m_mxInDeque.lock();
    while (m_quInData.size() != 0)
    {
        DATA data = move(m_quInData.front());
        m_quInData.pop_front();

        bool bZeroReceived = false;
        const size_t nToCopy = BUFLEN(data);
        m_atInBytes -= nToCopy;
        DatenDecode(&BUFFER(data)[0], nToCopy, bZeroReceived);
    }
    m_mxInDeque.unlock();

    return true;
}

bool SslTcpSocketImpl::SetConnectState()
{
    m_pSslCon = make_unique<SslConnection>(m_pClientCtx);
    m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocketImpl::Close, this)));
    m_pSslCon->SetUserData(0, reinterpret_cast<void*>(&SslTcpSocketImpl::fnForwarder));
    m_pSslCon->SetUserData(1, this);

    if (m_strTrustRootCert.size() > 0)
        m_pSslCon->SetTrustedRootCertificates(m_strTrustRootCert.c_str());

    ConEstablished(this);
    return true;
}

bool SslTcpSocketImpl::Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint/* = AF_UNSPEC*/)
{
    m_pSslCon = make_unique<SslConnection>(m_pClientCtx);
    m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocketImpl::Close, this)));
    m_pSslCon->SetUserData(0, reinterpret_cast<void*>(&SslTcpSocketImpl::fnForwarder));
    m_pSslCon->SetUserData(1, this);

    m_pSslCon->SetSniName(szIpToWhere);

    if (m_vProtoList.size() > 0)
        m_pSslCon->SetAlpnProtokollNames(m_vProtoList);
    if (m_strTrustRootCert.size() > 0)
        m_pSslCon->SetTrustedRootCertificates(m_strTrustRootCert.c_str());

    TcpSocketImpl::BindFuncConEstablished(bind(&SslTcpSocketImpl::ConEstablished, this, _1));
    return TcpSocketImpl::Connect(szIpToWhere, sPort, AddrHint);
}

int SslTcpSocketImpl::DatenEncode(const uint8_t* buf, size_t nAnzahl)
{
    if (m_bCloseReq == true)
        return -1;
    if (m_pSslCon->SSLGetShutdown() >= SSL_SENT_SHUTDOWN)
        return -1;

    if (buf == nullptr || nAnzahl == 0)
        return 0;

    const int iSslInit = m_pSslCon->SslInitFinished();
    if (iSslInit == 1)
    {
        int iErrorHint = 0;
        size_t nWritten = m_pSslCon->SslWrite(buf, nAnzahl, &iErrorHint);
        while (nWritten < nAnzahl && (iErrorHint == 0 || iErrorHint == SSL_ERROR_WANT_READ || iErrorHint == SSL_ERROR_WANT_WRITE) && m_pSslCon->GetShutDownFlag() == INT32_MIN)
        {
            unique_lock<mutex> lock(m_mxEnDecode);
            // Get the out Que of the openssl bio, the buffer is already encrypted
            size_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
            while (nOutDataSize > 0)
            {
                auto temp = make_unique<uint8_t[]>(nOutDataSize);
                size_t len = m_pSslCon->SslGetOutData(&temp[0], nOutDataSize);
                // Schreibt Daten in die SOCKET
                if (len > 0)
                {
                    m_mxOutDeque.lock();
                    m_atOutBytes += len;
                    m_quOutData.emplace_back(move(temp), len);
                    m_mxOutDeque.unlock();
                }

                nOutDataSize = m_pSslCon->SslGetOutDataSize();
            }
            lock.unlock();
            nWritten += m_pSslCon->SslWrite(&buf[nWritten], nAnzahl - nWritten, &iErrorHint);
        }

        unique_lock<mutex> lock(m_mxEnDecode);
        // Get the out Que of the openssl bio, the buffer is already encrypted
        size_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
        while (nOutDataSize > 0)
        {
            auto temp = make_unique<uint8_t[]>(nOutDataSize);
            const size_t len = m_pSslCon->SslGetOutData(&temp[0], nOutDataSize);
            // Schreibt Daten in die SOCKET
            if (len > 0)
            {
                m_mxOutDeque.lock();
                m_atOutBytes += len;
                m_quOutData.emplace_back(move(temp), len);
                m_mxOutDeque.unlock();
            }
            nOutDataSize = m_pSslCon->SslGetOutDataSize();
        }
        lock.unlock();
        return 1;
    }
    else
    {
        OutputDebugString(wstring(L"SSL not initialized: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
    }

    return 0;
}

void SslTcpSocketImpl::Close()
{
    //OutputDebugString(L"SslTcpSocketImpl::Close\r\n");
    m_bCloseReq = true;

    if (GetErrorNo() == 0)  // We get here not because of an error
    {
        if (m_pSslCon != nullptr && m_pSslCon->SSLGetShutdown() < SSL_SENT_SHUTDOWN)
        {
            bool bNewData = false;
            unique_lock<mutex> lock(m_mxEnDecode);
            size_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
            while (nOutDataSize > 0)
            {
                OutputDebugString(wstring(L"SslGetOutDataSize unexpected full: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
                auto temp = make_unique<uint8_t[]>(nOutDataSize);
                const size_t len = m_pSslCon->SslGetOutData(&temp[0], nOutDataSize);
                // Schreibt Daten in die SOCKET
                if (len > 0)
                {
                    m_mxOutDeque.lock();
                    m_atOutBytes += len;
                    m_quOutData.emplace_back(move(temp), len);
                    m_mxOutDeque.unlock();
                    bNewData = true;
                }
                nOutDataSize = m_pSslCon->SslGetOutDataSize();
            }
            lock.unlock();

            if (m_iSslInit == 1)
            {
                m_pSslCon->ShutDownConnection();
                // Get the out Que of the openssl bio, the buffer is already encrypted
                nOutDataSize = m_pSslCon->SslGetOutDataSize();
                while (nOutDataSize > 0)
                {
                    auto temp = make_unique<uint8_t[]>(nOutDataSize);
                    const size_t len = m_pSslCon->SslGetOutData(&temp[0], nOutDataSize);
                    // Schreibt Daten in die SOCKET
                    if (len > 0)
                    {
                        m_atOutBytes += len;
                        m_quOutData.emplace_back(move(temp), len);
                        bNewData = true;
                    }
                    nOutDataSize = m_pSslCon->SslGetOutDataSize();
                }
            }

            if (bNewData == true)
                TriggerWriteThread();
        }
    }

    TcpSocketImpl::Close();
}

function<void(TcpSocket*)> SslTcpSocketImpl::BindFuncConEstablished(function<void(TcpSocket*)> fClientConnected) noexcept
{
    m_fClientConnected.swap(fClientConnected);
    return fClientConnected;
}

function<void(TcpSocket*, void*)> SslTcpSocketImpl::BindFuncConEstablished(function<void(TcpSocket*, void*)> fClientConnected) noexcept
{
    m_fClientConnectedParam.swap(fClientConnected);
    return fClientConnected;
}

void SslTcpSocketImpl::ConEstablished(const TcpSocketImpl* const /*pTcpSocket*/)
{
    m_pSslCon->SSLSetConnectState();

    m_iSslInit = m_pSslCon->SSLDoHandshake();
    if (m_iSslInit <= 0)
    {
        const int iError = m_pSslCon->SSLGetError(m_iSslInit);
        if (iError != SSL_ERROR_WANT_READ)
        {
            m_iError = 0x80000000 | iError;
            m_iErrLoc = 15;
            OutputDebugString(wstring(L"SSL_error after SSL_Handshake: " + to_wstring(iError) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
            Close();
            return;
        }
    }

    bool bNewData = false;
    unique_lock<mutex> lock(m_mxEnDecode);
    size_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
    while (nOutDataSize > 0)
    {
        auto temp = make_unique<uint8_t[]>(nOutDataSize);
        size_t len = m_pSslCon->SslGetOutData(&temp[0], nOutDataSize);
        // Schreibt Daten in die SOCKET
        if (len > 0)
        {
            m_mxOutDeque.lock();
            m_atOutBytes += len;
            m_quOutData.emplace_back(move(temp), len);
            m_mxOutDeque.unlock();
            bNewData = true;
        }
        nOutDataSize = m_pSslCon->SslGetOutDataSize();
    }
    lock.unlock();

    if (bNewData == true)
        TriggerWriteThread();
}

int SslTcpSocketImpl::DatenDecode(const uint8_t* buffer, size_t nAnzahl, bool& bZeroReceived)
{
    if (buffer == nullptr || nAnzahl == 0)
        return 0;

    unique_lock<mutex> lock(m_mxEnDecode);
    const size_t nPut = m_pSslCon->SslPutInData(reinterpret_cast<const uint8_t*>(buffer), nAnzahl);
    lock.unlock();

    if (m_bCloseReq == true)
        return -1;

    if (m_pSslCon->SSLGetShutdown() >= SSL_RECEIVED_SHUTDOWN)
    {
        m_pSslCon->ShutDownConnection();
        Close();
        return -1;
    }

    m_iSslInit = m_pSslCon->SslInitFinished();
    if (m_iSslInit == 0)
    {
        m_iSslInit = m_pSslCon->SSLDoHandshake();

        bool bNewData = false;
        unique_lock<mutex> lock1(m_mxEnDecode);
        // Get the out Que of the openssl bio, the buffer is already encrypted
        size_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
        while (nOutDataSize > 0)
        {
            auto temp = make_unique<uint8_t[]>(nOutDataSize);
            size_t len = m_pSslCon->SslGetOutData(&temp[0], nOutDataSize);
            // Schreibt Daten in die SOCKET
            if (len > 0)
            {
                m_mxOutDeque.lock();
                m_atOutBytes += len;
                m_quOutData.emplace_back(move(temp), len);
                m_mxOutDeque.unlock();
                bNewData = true;
            }
            nOutDataSize = m_pSslCon->SslGetOutDataSize();
        }
        lock1.unlock();

        if (bNewData == true)
            TriggerWriteThread();

        if (m_iSslInit <= 0)
        {
            const int iError = m_pSslCon->SSLGetError(m_iSslInit);
            if (iError != SSL_ERROR_WANT_READ)
            {
                m_iError = 0x80000000 | iError;
                m_iErrLoc = 14;
                OutputDebugString(wstring(L"SSL_error: " + to_wstring(iError) + L", after SSL_do_handshake returned: " + to_wstring(m_iSslInit) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)()))).c_str());
                OutputDebugStringA(string(", msg: " + m_pSslCon->GetSslErrAsString()).c_str());
                if (m_fErrorParam)
                    m_fErrorParam(m_pBkRef, m_pvUserData);
                else if (m_fError)
                    m_fError(m_pBkRef);
                return -1;
            }
        }
        else
        {
            if (m_fClientConnectedParam)
                m_fClientConnectedParam(reinterpret_cast<SslTcpSocket*>(m_pBkRef), m_pvUserData);
            if (m_fClientConnected)
                m_fClientConnected(reinterpret_cast<SslTcpSocket*>(m_pBkRef));
        }
    }

    int iReturn = -1;
    if (m_iSslInit == 1)
    {
        auto Buffer = make_unique<uint8_t[]>(0x0000ffff);
        int iErrorHint = 0;
        size_t len = m_pSslCon->SslRead(&Buffer[0], 0x0000ffff, &iErrorHint); // get receive data from the SSL layer, and put it into the unencrypted receive Que
        while (len > 0)
        {
            auto tmp = make_unique<uint8_t[]>(len);
            copy_n(&Buffer[0], len, &tmp[0]);
            m_mxInDeque.lock();
            m_quInData.emplace_back(move(tmp), len);
            m_atInBytes += len;
            m_mxInDeque.unlock();
            iReturn = 1;

            len = m_pSslCon->SslRead(&Buffer[0], 0x0000ffff, &iErrorHint); // get receive data from the SSL layer, and put it into the unencrypted receive Que
        }

        bool bNewData = false;
        unique_lock<mutex> lock1(m_mxEnDecode);
        // Get the out Que of the openssl bio, the buffer is already encrypted
        size_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
        while (nOutDataSize > 0)
        {
            auto temp = make_unique<uint8_t[]>(nOutDataSize);
            size_t anz = m_pSslCon->SslGetOutData(&temp[0], nOutDataSize);
            // Schreibt Daten in die SOCKET
            if (anz > 0)
            {
                m_mxOutDeque.lock();
                m_atOutBytes += anz;
                m_quOutData.emplace_back(move(temp), anz);
                m_mxOutDeque.unlock();
                bNewData = true;
            }
            nOutDataSize = m_pSslCon->SslGetOutDataSize();
        }
        lock1.unlock();

        if (bNewData == true)
            TriggerWriteThread();

        m_mxOutDeque.lock();
        while (m_quTmpOutData.size() > 0)
        {
            DATA data = move(m_quTmpOutData.front());
            m_quTmpOutData.pop_front();
            m_mxOutDeque.unlock();
            Write((&BUFFER(data)[0]), BUFLEN(data));
            m_mxOutDeque.lock();
        }
        m_mxOutDeque.unlock();
        bZeroReceived = m_pSslCon->GetZeroReceived();
    }

    if (nPut != 0 && nPut != nAnzahl)
    {
        OutputDebugString(wstring(L"SslPutInData konnte nicht alles fassen on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
        return DatenDecode(&buffer[nPut], nAnzahl - nPut, bZeroReceived);
    }

    return iReturn;
}

void SslTcpSocketImpl::SetAlpnProtokollNames(const vector<string>& vProtoList)
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

SslTcpSocket* SslTcpSocketImpl::SwitchToSsl(TcpSocket* pTcpSocket)
{
    unique_ptr<BaseSocket> pSslTcpSocket = make_unique<SslTcpSocket>(pTcpSocket);
    SslTcpSocket* pSslTcpSock = dynamic_cast<SslTcpSocket*>(pSslTcpSocket.get());
    SslTcpSocketImpl* pSslTcpSocketImpl = dynamic_cast<SslTcpSocketImpl*>(pSslTcpSock->GetImpl());

    pSslTcpSocketImpl->m_fnSslEncode = bind(&SslTcpSocketImpl::DatenEncode, pSslTcpSocketImpl, _1, _2);
    pSslTcpSocketImpl->m_fnSslDecode = bind(&SslTcpSocketImpl::DatenDecode, pSslTcpSocketImpl, _1, _2, _3);

    lock_guard<mutex> lock(s_mxClientSocket);
    s_lstClientSocket.push_back(move(pSslTcpSocket));

    return pSslTcpSock;
}

//************************************************************************************

SslTcpServerImpl::SslTcpServerImpl(BaseSocket* pBkref) noexcept : TcpServerImpl(pBkref)
{
}

SslTcpSocket* SslTcpServerImpl::MakeClientConnection(const SOCKET& fSock)
{
    if (m_SslCtx.size() == 0)
        m_SslCtx.emplace_back(SslServerContext());

    unique_ptr<BaseSocket> pSslTcpSocket = make_unique<SslTcpSocket>();
    SslTcpSocket* pSslTcpSock = dynamic_cast<SslTcpSocket*>(pSslTcpSocket.get());
    SslTcpSocketImpl* pSslTcpSocketImpl = dynamic_cast<SslTcpSocketImpl*>(pSslTcpSock->GetImpl());

    try
    {
        pSslTcpSocketImpl->m_pSslCon = make_unique<SslConnection>(m_SslCtx.front());

        pSslTcpSocketImpl->m_fSock = fSock;
        pSslTcpSocketImpl->m_iShutDownState = 7;
        pSslTcpSocketImpl->m_pRefServSocket = dynamic_cast<SslTcpServer*>(m_pBkRef);
        pSslTcpSocketImpl->m_thWrite = thread(&TcpSocketImpl::WriteThread, pSslTcpSocketImpl);

        pSslTcpSocketImpl->m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocketImpl::Close, pSslTcpSocketImpl)));
        pSslTcpSocketImpl->m_pSslCon->SetUserData(0, reinterpret_cast<void*>(&SslTcpSocketImpl::fnForwarder));
        pSslTcpSocketImpl->m_pSslCon->SetUserData(1, dynamic_cast<SslTcpSocketImpl*>(pSslTcpSock->GetImpl()));
        pSslTcpSocketImpl->m_fnSslEncode = bind(&SslTcpSocketImpl::DatenEncode, pSslTcpSocketImpl, _1, _2);
        pSslTcpSocketImpl->m_fnSslDecode = bind(&SslTcpSocketImpl::DatenDecode, pSslTcpSocketImpl, _1, _2, _3);

        pSslTcpSocketImpl->m_pSslCon->SSLSetAcceptState();

        pSslTcpSocketImpl->SetSocketOption(fSock);
        pSslTcpSocketImpl->GetConnectionInfo();
    }

    catch (const int iErrNo)
    {
        pSslTcpSocketImpl->SetErrorNo(iErrNo);
    }

    lock_guard<mutex> lock(s_mxClientSocket);
    s_lstClientSocket.push_back(move(pSslTcpSocket));

    return pSslTcpSock;
}

bool SslTcpServerImpl::AddCertificate(const char* const szCAcertificate, const char* const szHostCertificate, const char* const szHostKey)
{
    m_SslCtx.emplace_back(SslServerContext());
    const int iRet = m_SslCtx.back().SetCertificates(szCAcertificate, szHostCertificate, szHostKey);
    if (iRet != 1)
    {
        OutputDebugString(wstring(L"Certificate could not be loaded, error: " + to_wstring(iRet) + L"\r\n").c_str());
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
    const bool bRet = m_SslCtx.back().SetDhParamFile(szDhParamFileName);
    if (bRet == false)
    {
        OutputDebugString(wstring(L"DH File could not be loaded\r\n").c_str());
        m_SslCtx.pop_back();
    }
    return bRet;
}

bool SslTcpServerImpl::SetCipher(const char* const szCipher) noexcept
{
    if (m_SslCtx.size() == 0)
        return false;
    return m_SslCtx.back().SetCipher(szCipher);
}

void SslTcpServerImpl::SetAlpnProtokollNames(const vector<string>& vStrProtoNames)
{
    for (auto& ctx : m_SslCtx)
        ctx.SetAlpnProtokollNames(vStrProtoNames);
}

//************************************************************************************

SslUdpSocketImpl::SslUdpSocketImpl(BaseSocket* pBkRef) : UdpSocketImpl(pBkRef), m_bCloseReq(false)
{
    m_fnSslEncode = bind(&SslUdpSocketImpl::DatenEncode, this, _1, _2, _3);
    m_fnSslDecode = bind(&SslUdpSocketImpl::DatenDecode, this, _1, _2, _3);
}

SslUdpSocketImpl::~SslUdpSocketImpl()
{
}

bool SslUdpSocketImpl::AddCertificate(const char* const szHostCertificate, const char* const szHostKey)
{
    m_pUdpCtx.SetCertificates(szHostCertificate, szHostKey);
    return true;
}

bool SslUdpSocketImpl::CreateServerSide(const char* const szIpToWhere, const uint16_t sPort, const char* const szIpToBind/* = nullptr*/)
{
    const bool bRet = UdpSocketImpl::Create(szIpToWhere, sPort, szIpToBind);
    if (bRet == true)
    {
        m_pSslCon = make_unique<SslConnection>(m_pUdpCtx);
        m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocketImpl::Close, this)));

        //SSL_set_info_callback((*m_pSslCon)(), ssl_info_callbackServer);

        m_pSslCon->SSLSetAcceptState();
    }
    return bRet;
}

bool SslUdpSocketImpl::CreateClientSide(const char* const szIpToWhere, const uint16_t sPort, const char* const szDestAddr, const char* const szIpToBind/* = nullptr*/)
{
    m_strDestAddr = szDestAddr;
    const bool bRet = UdpSocketImpl::Create(szIpToWhere, sPort, szIpToBind);
    if (bRet == true)
    {
        m_pSslCon = make_unique<SslConnection>(m_pUdpCtx);
        m_pSslCon->SetErrorCb(function<void()>(bind(&BaseSocketImpl::Close, this)));

        //SSL_set_info_callback((*m_pSslCon)(), ssl_info_callbackClient);

        m_pSslCon->SSLSetConnectState();

        const int iSslInit = m_pSslCon->SSLDoHandshake();
        if (iSslInit <= 0)
        {
            const int iError = m_pSslCon->SSLGetError(iSslInit);
            if (iError != SSL_ERROR_WANT_READ)
            {
                m_iError = 0x80000000 | iError;
                m_iErrLoc = 15;
                OutputDebugString(wstring(L"SSL_error after SSL_Handshake: " + to_wstring(iError) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
                Close();
                return false;
            }
        }

        unique_lock<mutex> lock(m_mxEnDecode);
        bool bNewData = false;

        size_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
        while (nOutDataSize > 0)
        {
            auto temp = make_unique<uint8_t[]>(nOutDataSize);
            size_t len = m_pSslCon->SslGetOutData(&temp[0], nOutDataSize);
            // Schreibt Daten in die SOCKET
            if (len > 0)
            {
                m_mxOutDeque.lock();
                m_atOutBytes += len;
                m_quOutData.emplace_back(move(temp), len, m_strDestAddr);
                m_mxOutDeque.unlock();
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
int SslUdpSocketImpl::DatenEncode(const uint8_t* buf, size_t nAnzahl, const string& strAddress)
{
    if (m_bCloseReq == true)
        return -1;
    if (m_pSslCon->SSLGetShutdown() >= SSL_SENT_SHUTDOWN)
        return -1;

    if (buf == nullptr || nAnzahl == 0)
        return 0;

    const int iSslInit = m_pSslCon->SslInitFinished();
    if (iSslInit == 1)
    {
        int iErrorHint = 0;
        size_t nWritten = m_pSslCon->SslWrite(buf, nAnzahl, &iErrorHint);
        while (nWritten < nAnzahl && (iErrorHint == 0 || iErrorHint == SSL_ERROR_WANT_READ || iErrorHint == SSL_ERROR_WANT_WRITE) && m_pSslCon->GetShutDownFlag() == INT32_MIN)
        {
            unique_lock<mutex> lock(m_mxEnDecode);
            // Get the out Que of the openssl bio, the buffer is already encrypted
            size_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
            while (nOutDataSize > 0)
            {
                auto temp = make_unique<uint8_t[]>(nOutDataSize);
                const size_t len = m_pSslCon->SslGetOutData(&temp[0], nOutDataSize);
                // Schreibt Daten in die SOCKET
                if (len > 0)
                {
                    m_mxOutDeque.lock();
                    m_atOutBytes += len;
                    m_quOutData.emplace_back(move(temp), len, strAddress);
                    m_mxOutDeque.unlock();
                }

                nOutDataSize = m_pSslCon->SslGetOutDataSize();
            }
            lock.unlock();
            nWritten += m_pSslCon->SslWrite(&buf[nWritten], nAnzahl - nWritten, &iErrorHint);
        }

        unique_lock<mutex> lock(m_mxEnDecode);
        // Get the out Que of the openssl bio, the buffer is already encrypted
        size_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
        while (nOutDataSize > 0)
        {
            auto temp = make_unique<uint8_t[]>(nOutDataSize);
            const size_t len = m_pSslCon->SslGetOutData(&temp[0], nOutDataSize);
            // Schreibt Daten in die SOCKET
            if (len > 0)
            {
                m_mxOutDeque.lock();
                m_atOutBytes += len;
                m_quOutData.emplace_back(move(temp), len, strAddress);
                m_mxOutDeque.unlock();
            }
            nOutDataSize = m_pSslCon->SslGetOutDataSize();
        }
        lock.unlock();
        return 1;
    }
    else
    {
        OutputDebugString(wstring(L"SSL not initialized: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
    }

    return 0;
}

void SslUdpSocketImpl::Close()
{
    //OutputDebugString(L"SslTcpSocketImpl::Close\r\n");
    m_bCloseReq = true;

    if (GetErrorNo() == 0)  // We get here not because of an error
    {
        if (m_pSslCon->SSLGetShutdown() < SSL_SENT_SHUTDOWN)
        {
            unique_lock<mutex> lock(m_mxEnDecode);
            bool bNewData = false;

            size_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
            while (nOutDataSize > 0)
            {
                OutputDebugString(wstring(L"SslGetOutDataSize unexpected full: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
                auto temp = make_unique<uint8_t[]>(nOutDataSize);
                const size_t len = m_pSslCon->SslGetOutData(&temp[0], nOutDataSize);
                // Schreibt Daten in die SOCKET
                if (len > 0)
                {
                    m_mxOutDeque.lock();
                    m_atOutBytes += len;
                    m_quOutData.emplace_back(move(temp), len, m_strDestAddr);
                    m_mxOutDeque.unlock();
                    bNewData = true;
                }
                nOutDataSize = m_pSslCon->SslGetOutDataSize();
            }

            m_pSslCon->ShutDownConnection();
            // Get the out Que of the openssl bio, the buffer is already encrypted
            nOutDataSize = m_pSslCon->SslGetOutDataSize();
            while (nOutDataSize > 0)
            {
                auto temp = make_unique<uint8_t[]>(nOutDataSize);
                const size_t len = m_pSslCon->SslGetOutData(&temp[0], nOutDataSize);
                // Schreibt Daten in die SOCKET
                if (len > 0)
                {
                    m_mxOutDeque.lock();
                    m_atOutBytes += len;
                    m_quOutData.emplace_back(move(temp), len, m_strDestAddr);
                    m_mxOutDeque.unlock();
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

function<void(UdpSocket*, void*)> SslUdpSocketImpl::BindFuncSslInitDone(function<void(UdpSocket*, void*)> fSllInitDone) noexcept
{
    m_fSllInitDoneParam.swap(fSllInitDone);
    return fSllInitDone;
}

int SslUdpSocketImpl::DatenDecode(const uint8_t* buffer, size_t nAnzahl, const string& strAddress)
{
    if (buffer == nullptr || nAnzahl == 0)
        return 0;

    unique_lock<mutex> lock(m_mxEnDecode);
    const size_t nPut = m_pSslCon->SslPutInData(buffer, nAnzahl);
    lock.unlock();

    if (m_bCloseReq == true)
        return -1;

    if (m_pSslCon->SSLGetShutdown() >= SSL_RECEIVED_SHUTDOWN)
    {
        m_pSslCon->ShutDownConnection();
        Close();
        return -1;
    }

    int iSslInit = m_pSslCon->SslInitFinished();
    if (iSslInit == 0)
    {
        iSslInit = m_pSslCon->SSLDoHandshake();

        bool bNewData = false;
        unique_lock<mutex> lock1(m_mxEnDecode);
        // Get the out Que of the openssl bio, the buffer is already encrypted
        size_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
        while (nOutDataSize > 0)
        {
            auto temp = make_unique<uint8_t[]>(nOutDataSize);
            const size_t len = m_pSslCon->SslGetOutData(&temp[0], nOutDataSize);
            // Schreibt Daten in die SOCKET
            if (len > 0)
            {
                m_mxOutDeque.lock();
                m_atOutBytes += len;
                m_quOutData.emplace_back(move(temp), len, strAddress);
                m_mxOutDeque.unlock();
                bNewData = true;
            }
            nOutDataSize = m_pSslCon->SslGetOutDataSize();
        }
        lock1.unlock();

        if (bNewData == true)
            TriggerWriteThread();

        if (iSslInit <= 0)
        {
            const int iError = m_pSslCon->SSLGetError(iSslInit);
            if (iError != SSL_ERROR_WANT_READ)
            {
                m_iError = 0x80000000 | iError;
                m_iErrLoc = 14;
                OutputDebugString(wstring(L"SSL_error: " + to_wstring(iError) + L", after SSL_do_handshake returned: " + to_wstring(iSslInit) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)()))).c_str());
                OutputDebugStringA(string(", msg: " + m_pSslCon->GetSslErrAsString()).c_str());
                if (m_fErrorParam && m_bStop == false)
                    m_fErrorParam(m_pBkRef, m_pvUserData);
                else if (m_fError && m_bStop == false)
                    m_fError(m_pBkRef);
                return -1;
            }
        }
        else
        {
            if (m_fSllInitDoneParam != nullptr)
                m_fSllInitDoneParam(dynamic_cast<UdpSocket*>(m_pBkRef), m_pvUserData);
            else if (m_fSllInitDone != nullptr)
                m_fSllInitDone(dynamic_cast<UdpSocket*>(m_pBkRef));
        }
    }

    int iReturn = -1;
    if (iSslInit == 1)
    {
        auto Buffer = make_unique<uint8_t[]>(0x0000ffff);
        int iErrorHint = 0;
        size_t len = m_pSslCon->SslRead(&Buffer[0], 0x0000ffff, &iErrorHint); // get receive data from the SSL layer, and put it into the unencrypted receive Que
        while (len > 0)
        {
            auto tmp = make_unique<uint8_t[]>(len);
            copy_n(&Buffer[0], len, &tmp[0]);
            m_mxInDeque.lock();
            m_quInData.emplace_back(move(tmp), len, strAddress);
            m_atInBytes += len;
            m_mxInDeque.unlock();

            len = m_pSslCon->SslRead(&Buffer[0], 0x0000ffff, &iErrorHint); // get receive data from the SSL layer, and put it into the unencrypted receive Que
        }
        iReturn = 1;

        bool bNewData = false;
        unique_lock<mutex> lock1(m_mxEnDecode);
        // Get the out Que of the openssl bio, the buffer is already encrypted
        size_t nOutDataSize = m_pSslCon->SslGetOutDataSize();
        while (nOutDataSize > 0)
        {
            auto temp = make_unique<uint8_t[]>(nOutDataSize);
            const size_t anz = m_pSslCon->SslGetOutData(&temp[0], nOutDataSize);
            // Schreibt Daten in die SOCKET
            if (anz > 0)
            {
                m_mxOutDeque.lock();
                m_atOutBytes += anz;
                m_quOutData.emplace_back(move(temp), anz, strAddress);
                m_mxOutDeque.unlock();
                bNewData = true;
            }
            nOutDataSize = m_pSslCon->SslGetOutDataSize();
        }
        lock1.unlock();

        if (bNewData == true)
            TriggerWriteThread();
    }

    if (nPut != 0 && nPut != nAnzahl)
    {
        OutputDebugString(wstring(L"SslPutInData konnte nicht alles fassen on ssl context: " + to_wstring(reinterpret_cast<size_t>((*m_pSslCon)())) + L"\r\n").c_str());
        return DatenDecode(&buffer[nPut], nAnzahl - nPut, strAddress);
    }

    return iReturn;
}

#endif // WITHOUT_OPENSSL
