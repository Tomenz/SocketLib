#pragma once
#ifndef OPENSSLWRAPPER
#define OPENSSLWRAPPER

// perl Configure debug-VC-WIN32 no-asm no-ssl2 no-ssl3 no-shared no-comp no-buf-freelists no-idea no-mdc2 no-rc5 -D_USING_V110_SDK71_
// ms\do_ms.bat
// nmake -f ms\nt.mak |  nmake -f ms\ntdll.mak |  nmake -f ms\nt.mak clean |  nmake -f ms\nt.mak clean
#if defined(_WIN32) || defined(_WIN64)
#include "./openssl/ssl.h"
#include "./openssl/engine.h"
#else
#include <openssl/ssl.h>
#include <openssl/engine.h>
#endif

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
        static void CbLocking(int iMode, int iType, const char*, int iLine);

    private:
        static unique_ptr<mutex[]> m_pmutLocks;
    };


    class SslContext
    {
    public:
        SslContext(const SSL_METHOD* sslMethod);
        virtual ~SslContext();
        SSL_CTX* operator() ();

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
        void SetAlpnProtokollNames(vector<string> vProtoList);
        void SetTrustedRootCertificates(const char* szTrustRootCert);
    };

    class SslServerContext : public SslContext
    {
    public:
        SslServerContext();
        string& GetCertCommonName();
        int SetCertificates(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey);
        void AddVirtualHost(vector<shared_ptr<SslServerContext>>* pSslCtx);

    private:
        static int ALPN_CB(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg);
//      static int NPN_CB(SSL *ssl, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg);
        static int SNI_CB(SSL *ssl, char iCmd, void* arg);

    private:
        string m_strCertComName;
    };

    class SslConnetion
    {
    public:
        SslConnetion(SslContext* ctx, const char* szName = 0);
        ~SslConnetion();
//      static long CbBioInfo(struct bio_st* pBioInfo, int iInt1, const char* cpBuf, int iInt2, long l1, long lRet);
        SSL* operator() ();
        void SetErrorCb(function<void()> fError);
        uint32_t SslGetOutDataSize();
//      size_t SslGetOutwDataSize();
//      size_t SslGetInrDataSize();
//      size_t SslGetInwDataSize();
        uint32_t SslGetOutData(uint8_t* szBuffer, uint32_t nBufLen);
        uint32_t SslPutInData(uint8_t* szBuffer, uint32_t nWriteLen);
        bool HandShakeComplet();
        int GetShutDownFlag();
        uint32_t SslRead(uint8_t* szBuffer, uint32_t nBufLen);
        size_t SslWrite(uint8_t* szBuffer, uint32_t nWriteLen);
        int ShutDownConnection();
        void SetAlpnProtokollNames(vector<string> vProtoList);
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

        const char* m_szName;
    };

    // Initialize the OpenSSL Library
    static InitOpenSSL* OpenSSLInit = InitOpenSSL::GetInstance();
}

#endif
