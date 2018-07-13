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
#ifndef OPENSSLWRAPPER
#define OPENSSLWRAPPER

// perl Configure VC-WIN32 no-asm no-ssl2 no-ssl3 no-shared no-comp no-buf-freelists no-idea no-mdc2 no-rc5 -D_USING_V110_SDK71_
// perl Configure VC-WIN64A no-asm no-ssl2 no-ssl3 no-shared no-comp no-buf-freelists no-idea no-mdc2 no-rc5 -D_USING_V110_SDK71_
// ms\do_ms.bat oder ms\do_win64a
// nmake -f ms\nt.mak |  nmake -f ms\ntdll.mak |  nmake -f ms\nt.mak clean |  nmake -f ms\nt.mak clean

// From openssl ver. 1.1.0
// perl Configure VC-WIN32 no-asm -D_USING_V110_SDK71_ --api=1.1.0
// perl Configure VC-WIN64A no-asm -D_USING_V110_SDK71_ --api=1.1.0
// Replace the /MD with /MT in the makefile
// nmake
#include <openssl/ssl.h>
#include <openssl/engine.h>

namespace OpenSSLWrapper
{
    using namespace std;

    class InitOpenSSL
    {
    public:
        static InitOpenSSL* GetInstance();
        ~InitOpenSSL();

    private:
        InitOpenSSL();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        static void CbLocking(int iMode, int iType, const char*, int iLine);

    private:
        static unique_ptr<mutex[]> m_pmutLocks;
#endif
    };


    class SslContext
    {
    public:
        explicit SslContext(const SSL_METHOD* sslMethod);
        virtual ~SslContext();
        SSL_CTX* operator() ();
        //SslContext(const SslContext&) = delete;
        SslContext(SslContext& src) {
            m_ctx = src.m_ctx; src.m_ctx = nullptr;
        }
        //SslContext(SslContext&&) = delete;
        SslContext& operator=(SslContext&&) = delete;
        SslContext& operator=(const SslContext&) = delete;

#ifdef _DEBUG
    private:
        static void SSLInfo(const SSL *ssl, int type, int val);
        static void SSLMsgCB(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
#endif

    protected:
        SSL_CTX* m_ctx;
    };

    class SslClientContext : public SslContext
    {
    public:
        SslClientContext();
        void SetAlpnProtokollNames(vector<string>& vProtoList);
        void SetTrustedRootCertificates(const char* szTrustRootCert);
        SslClientContext(const SslClientContext&) = delete;
        SslClientContext(SslClientContext&&) = delete;
        SslClientContext& operator=(SslClientContext&&) = delete;
        SslClientContext& operator=(const SslClientContext&) = delete;
    };

    class SslServerContext : public SslContext
    {
    public:
        SslServerContext();
        string& GetCertCommonName() noexcept;
        int SetCertificates(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey);
        void AddVirtualHost(vector<SslServerContext>* pSslCtx);
        bool SetDhParamFile(const char* const szDhParamFile);
        SslServerContext(SslServerContext& src) : SslContext(src)
        {
            m_strCertComName = src.m_strCertComName;
            m_vstrAltNames = src.m_vstrAltNames;
        }
        //SslServerContext(SslServerContext&&) = delete;
        SslServerContext& operator=(SslServerContext&&) = delete;
        SslServerContext& operator=(const SslServerContext&) = delete;

    private:
        static int ALPN_CB(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg);
//      static int NPN_CB(SSL *ssl, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg);
        static int SNI_CB(SSL *ssl, char iCmd, void* arg);

    private:
        string m_strCertComName;
        vector<string> m_vstrAltNames;
    };

    class SslUdpContext : public SslContext
    {
    public:
        SslUdpContext();
        int SetCertificates(const char* szHostCertificate, const char* szHostKey);
    private:
        static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);
    private:
        string m_strCertComName;
    };

    class SslConnetion
    {
    public:
        explicit SslConnetion(SslContext& ctx);
        ~SslConnetion();
//      static long CbBioInfo(struct bio_st* pBioInfo, int iInt1, const char* cpBuf, int iInt2, long l1, long lRet);
        SSL* operator() ();
        void SetErrorCb(const function<void()>& fError) noexcept;
        void SetUserData(int iIndex, void* pVoid) noexcept;
        uint32_t SslGetOutDataSize();
//      size_t SslGetOutwDataSize();
//      size_t SslGetInrDataSize();
//      size_t SslGetInwDataSize();
        uint32_t SslGetOutData(uint8_t* szBuffer, uint32_t nBufLen);
        uint32_t SslPutInData(uint8_t* szBuffer, uint32_t nWriteLen);
//        bool HandShakeComplet();
        int GetShutDownFlag() noexcept;
        uint32_t SslRead(uint8_t* szBuffer, uint32_t nBufLen);
        uint32_t SslWrite(const uint8_t* szBuffer, uint32_t nWriteLen);
        int ShutDownConnection();
        void SetAlpnProtokollNames(vector<string>& vProtoList);
        string GetSelAlpnProtocol();
        void SetTrustedRootCertificates(const char* szFileName);
        long CheckServerCertificate(const char* szHostName);

    private:
        SSL* m_ssl;
        BIO* m_rbio;
        BIO* m_wbio;
        int  m_iShutDownFlag;
        function<void()> m_fError;
        int m_iWantState;
    };
}

#endif
