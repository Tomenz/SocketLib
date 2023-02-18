/* Copyright (C) 2016-2020 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
*/

#ifndef OPENSSLWRAPPER_H
#define OPENSSLWRAPPER_H

#ifndef WITHOUT_OPENSSL

// perl Configure VC-WIN32 no-asm no-ssl2 no-ssl3 no-shared no-comp no-buf-freelists no-idea no-mdc2 no-rc5 -D_USING_V110_SDK71_
// perl Configure VC-WIN64A no-asm no-ssl2 no-ssl3 no-shared no-comp no-buf-freelists no-idea no-mdc2 no-rc5 -D_USING_V110_SDK71_
// ms\do_ms.bat oder ms\do_win64a
// nmake -f ms\nt.mak |  nmake -f ms\ntdll.mak |  nmake -f ms\nt.mak clean |  nmake -f ms\nt.mak clean

// From openssl ver. 1.1.0
// perl Configure VC-WIN32 enable-tls1_3 no-asm no-deprecated (-D_USING_V110_SDK71_ --api=1.1.0)
// perl Configure VC-WIN64A enable-tls1_3 no-asm no-deprecated (-D_USING_V110_SDK71_ --api=1.1.0)
// Replace the /MD with /MT in the makefile
// nmake build_libs
// nmake distclean
#include <openssl/ssl.h>
#include <openssl/engine.h>

#include <mutex>
#include <vector>
#include <functional>

namespace OpenSSLWrapper
{
    using namespace std;

    class InitOpenSSL
    {
    public:
        static const InitOpenSSL* GetInstance();
        ~InitOpenSSL();
        InitOpenSSL(const InitOpenSSL&) = delete;
        InitOpenSSL(InitOpenSSL&&) = delete;
        InitOpenSSL& operator=(const InitOpenSSL&) = delete;
        InitOpenSSL& operator=(InitOpenSSL&&) = delete;

    private:
        InitOpenSSL();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        static void CbLocking(int iMode, int iType, const char*, int iLine);

    private:
        static unique_ptr<mutex[]> m_pmutLocks;
#endif
        string strVersion;
    };

    bool GetCertInformation(const X509* cert, string& strCommonName, vector<string>& vstrAltNames);

    class SslContext
    {
    public:
        SslContext() = delete;
        explicit SslContext(const SSL_METHOD* sslMethod) noexcept;
        virtual ~SslContext();

        SSL_CTX* operator() ();
        SslContext(const SslContext&) = delete;
        explicit SslContext(SslContext&& src) noexcept
        {
            m_ctx = move(src.m_ctx);
            src.m_ctx = nullptr;
        }
        SslContext& operator=(SslContext&&) = delete;
        SslContext& operator=(const SslContext&) = delete;

        int SetCertificates(const char* szHostCertificate, const char* szHostKey);
        string& GetCertCommonName() noexcept;

#ifdef _DEBUG
    private:
        static void SSLInfo(const SSL *ssl, int type, int val) noexcept;
        static void SSLMsgCB(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) noexcept;
#endif

    protected:
        SSL_CTX* m_ctx;
        string   m_strCertComName;
        vector<string> m_vstrAltNames;
    };

    class SslClientContext : public SslContext
    {
    public:
        SslClientContext() noexcept;
        void SetAlpnProtokollNames(const vector<string>& vProtoList);
        void SetTrustedRootCertificates(const char* szTrustRootCert) noexcept;
        SslClientContext(const SslClientContext&) = delete;
        SslClientContext(SslClientContext&&) = delete;
        SslClientContext& operator=(SslClientContext&&) = delete;
        SslClientContext& operator=(const SslClientContext&) = delete;
    };

    class SslServerContext : public SslContext
    {
    public:
        explicit SslServerContext() noexcept;
        ~SslServerContext() = default;
        int SetCertificates(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey);
        void AddVirtualHost(vector<SslServerContext>* pSslCtx) noexcept;
        bool SetDhParamFile(const char* const szDhParamFile);
        bool SetCipher(const char* const szCipher) noexcept;
        void SetAlpnProtokollNames(const vector<string>& vStrList);
        SslServerContext(const SslServerContext& src) = delete;
        explicit SslServerContext(SslServerContext&& src) noexcept : SslContext(move(src))
        {
            m_strCertComName = move(src.m_strCertComName);
            m_vstrAltNames = move(src.m_vstrAltNames);
            m_vstrAlpnProtoList = move(src.m_vstrAlpnProtoList);
        }
        SslServerContext& operator=(SslServerContext&&) = delete;
        SslServerContext& operator=(const SslServerContext&) = delete;

    private:
        static int ALPN_CB(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg);
//      static int NPN_CB(SSL *ssl, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg);
        static int SNI_CB(SSL *ssl, char iCmd, void* arg);

    private:
        vector<string> m_vstrAlpnProtoList;
    };

    class SslUdpContext : public SslContext
    {
    public:
        SslUdpContext() noexcept;
        ~SslUdpContext() = default;
        SslUdpContext(const SslUdpContext&) = delete;
        SslUdpContext(SslUdpContext&&) = delete;
        SslUdpContext& operator=(const SslUdpContext&) = delete;
        SslUdpContext& operator=(SslUdpContext&&) = delete;
    private:
        static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) noexcept;
    };

    class SslConnection
    {
    public:
        explicit SslConnection(SslContext& ctx);
        ~SslConnection();
        SslConnection(const SslConnection&) = delete;
        SslConnection(SslConnection&&) = delete;
        SslConnection& operator=(const SslConnection&) = delete;
        SslConnection& operator=(SslConnection&&) = delete;
//      static long CbBioInfo(struct bio_st* pBioInfo, int iInt1, const char* cpBuf, int iInt2, long l1, long lRet);
        SSL* operator() ();
        void SetErrorCb(const function<void()>& fError);
        void SetUserData(int iIndex, void* pVoid) noexcept;
        void SSLSetAcceptState();
        void SSLSetConnectState();
        int SSLDoHandshake();
        int SslInitFinished();
        void SSLSetShutdown(int iState);
        int SSLGetShutdown();
        int SSLGetError(int iResult);
        size_t SslGetOutDataSize();
//      size_t SslGetOutwDataSize();
//      size_t SslGetInrDataSize();
//      size_t SslGetInwDataSize();
        size_t SslGetOutData(uint8_t* szBuffer, size_t nBufLen);
        size_t SslPutInData(const uint8_t* szBuffer, size_t nWriteLen);
        int GetShutDownFlag() noexcept;
        bool GetZeroReceived() noexcept;
        size_t SslRead(uint8_t* szBuffer, size_t nBufLen, int* iErrorHint = nullptr);
        size_t SslWrite(const uint8_t* szBuffer, size_t nWriteLen, int* iErrorHint = nullptr);
        int ShutDownConnection(int* iErrorHint = nullptr);
        void SetAlpnProtokollNames(const vector<string>& vProtoList);
        string GetSelAlpnProtocol();
        int SetTrustedRootCertificates(const char* szFileName) noexcept;
        long SetSniName(const char* szServerName) noexcept;
        long CheckServerCertificate(const char* szHostName);
        string GetSslErrAsString();

    private:
        SSL* m_ssl;
        BIO* m_rbio;
        BIO* m_wbio;
        int  m_iShutDownFlag;
        bool m_bZeroReceived;
        function<void()> m_fError;
        int m_iWantState;
        mutex m_mxSsl;
    };
}

#endif // WITHOUT_OPENSSL

#endif // OPENSSLWRAPPER_H
