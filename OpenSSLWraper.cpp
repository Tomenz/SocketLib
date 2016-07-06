
#include <memory>
#include <mutex>
#include <vector>
#include <iterator>
#include <algorithm>
#include <fstream>
#include "OpenSSLWraper.h"

#if defined(_WIN32) || defined(_WIN64)
#include "./openssl/conf.h"
#ifdef _WIN64
#pragma comment(lib, "ssleay64.lib")
#pragma comment(lib, "libeay64.lib")
#else
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")
#endif
#else
#include <openssl/conf.h>
#endif

#define WHERE_INFO(ssl, w, flag, msg) { if (w & flag) /*wcout << "\t" << msg << "  - " << SSL_state_string(ssl) << "  - " << SSL_state_string_long(ssl) << endl*/; }

namespace OpenSSLWrapper
{
    // Initialize the OpenSSL Library
    const InitOpenSSL* OpenSSLInit = InitOpenSSL::GetInstance();

    unique_ptr<mutex[]> InitOpenSSL::m_pmutLocks;

    InitOpenSSL* InitOpenSSL::GetInstance()
    {
        static InitOpenSSL iniOpenSsl;
        return &iniOpenSsl;
    }

    InitOpenSSL::~InitOpenSSL()
    {
        CRYPTO_set_locking_callback(nullptr);

        /* thread-local cleanup */
        ERR_remove_thread_state(nullptr);

        /* thread-safe cleanup */
        ENGINE_cleanup();
        CONF_modules_unload(1);

        /* global application exit cleanup (after all SSL activity is shutdown) */
        ERR_free_strings();
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
    }

    InitOpenSSL::InitOpenSSL()
    {
        SSL_library_init();
        SSL_load_error_strings();
        ERR_load_BIO_strings();
        OpenSSL_add_all_algorithms();

        m_pmutLocks = make_unique<mutex[]>(CRYPTO_num_locks());
        CRYPTO_set_locking_callback(CbLocking);
    }

    void InitOpenSSL::CbLocking(int iMode, int iType, const char*, int iLine)
    {
        if (iMode & CRYPTO_LOCK)
            m_pmutLocks.get()[iType].lock();
        else
            m_pmutLocks.get()[iType].unlock();
    }


    SslContext::SslContext(const SSL_METHOD* sslMethod) : m_ctx(SSL_CTX_new(sslMethod))
    {
#ifdef _DEBUG
        //            SSL_CTX_set_info_callback(m_ctx, SSLInfo);
        //            SSL_CTX_set_msg_callback(m_ctx, SSLMsgCB);
#endif
    }

    SslContext::~SslContext()
    {
        if (nullptr != m_ctx)
            SSL_CTX_free(m_ctx);
    }

    SSL_CTX* SslContext::operator() ()
    {
        if (nullptr == m_ctx)
            throw runtime_error("Not Initialized");
        return m_ctx;
    }

#ifdef _DEBUG
    void SslContext::SSLInfo(const SSL *ssl, int type, int val)
    {
        if (val == 0)
        {
            //wcout << "ssl error occured." << endl;
            return;
        }

        //WHERE_INFO(ssl, type, SSL_CB_LOOP, "LOOP");
        //WHERE_INFO(ssl, type, SSL_CB_EXIT, "EXIT");
        //WHERE_INFO(ssl, type, SSL_CB_READ, "READ");
        //WHERE_INFO(ssl, type, SSL_CB_WRITE, "WRITE");
        //WHERE_INFO(ssl, type, SSL_CB_ALERT, "ALERT");
        //WHERE_INFO(ssl, type, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");

    }

    void SslContext::SSLMsgCB(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
    {
        //wcout << "\tMessage callback with length: " << len << endl;
    }
#endif


    SslClientContext::SslClientContext() : SslContext(SSLv23_client_method())
    {
        SSL_CTX_set_options(m_ctx, (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
        SSL_CTX_set_mode(m_ctx, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_mode(m_ctx, SSL_MODE_RELEASE_BUFFERS);

        SSL_CTX_set_ecdh_auto(m_ctx, 1);

        SSL_CTX_set_cipher_list(m_ctx, "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4");
    }

    void SslClientContext::SetAlpnProtokollNames(vector<string> vProtoList)
    {
        if (vProtoList.size() > 0)
        {
            vector<unsigned char> proto_list;
            for (const auto &proto : vProtoList)
            {
                proto_list.push_back(static_cast<char>(proto.size()));
                copy_n(proto.c_str(), proto.size(), back_inserter(proto_list));
            }
            SSL_CTX_set_alpn_protos(m_ctx, proto_list.data(), static_cast<int>(proto_list.size()));
        }
    }

    void SslClientContext::SetTrustedRootCertificates(const char* szTrustRootCert)
    {
        SSL_CTX_load_verify_locations(m_ctx, szTrustRootCert, nullptr);
        //SSL_CTX_set_default_verify_paths(ctx);
    }


    SslServerContext::SslServerContext() : SslContext(SSLv23_server_method())
    {
        //SSL_CTX_set_options(m_ctx, (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
        SSL_CTX_set_options(m_ctx, (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) | SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
        SSL_CTX_set_mode(m_ctx, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_mode(m_ctx, SSL_MODE_RELEASE_BUFFERS);
        SSL_CTX_set_mode(m_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
        SSL_CTX_set_verify(m_ctx, SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set_mode(m_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

        SSL_CTX_set_ecdh_auto(m_ctx, 1);

        //https://raymii.org/s/tutorials/Strong_SSL_Security_On_Apache2.html
//        SSL_CTX_set_cipher_list(m_ctx, "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4");
        SSL_CTX_set_cipher_list(m_ctx, "EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA:EECDH:EDH+AESGCM:EDH:+3DES:ECDH+AESGCM:ECDH+AES:ECDH:AES:HIGH:MEDIUM:!RC4:!CAMELLIA:!SEED:!aNULL:!MD5:!eNULL:!LOW:!EXP:!DSS:!PSK:!SRP");

        SSL_CTX_set_alpn_select_cb(m_ctx, ALPN_CB, 0);
        //SSL_CTX_set_next_proto_select_cb(m_ctx, NPN_CB, 0);
        SSL_CTX_set_tlsext_servername_arg(m_ctx, nullptr);
        SSL_CTX_set_tlsext_servername_callback(m_ctx, SNI_CB);
    }

    string& SslServerContext::GetCertCommonName()
    {
        return m_strCertComName;
    }

    int SslServerContext::SetCertificates(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey)
    {
        if (SSL_CTX_use_certificate_chain_file(m_ctx, szCAcertificate) != 1)
            return -1;// throw runtime_error("error loading CA root certificate");

        if (SSL_CTX_use_certificate_file(m_ctx, szHostCertificate, SSL_FILETYPE_PEM) != 1)
            return -2;//throw runtime_error("error loading host certificate");

        if (SSL_CTX_use_PrivateKey_file(m_ctx, szHostKey, SSL_FILETYPE_PEM) != 1)
            return -3;//throw runtime_error("error loading certificate key");

        if (SSL_CTX_check_private_key(m_ctx) != 1)
            return -4;//throw runtime_error("error key not matching certificate");

        X509 *cert = SSL_CTX_get0_certificate(m_ctx);
        if (cert)
        {
            char caBuf[256];
            X509_NAME_oneline(X509_get_subject_name(cert), caBuf, 256);

            m_strCertComName = caBuf;
            size_t nPos = m_strCertComName.find("/CN=");
            if (nPos != string::npos)
            {
                m_strCertComName.erase(0, nPos + 4);
                nPos = m_strCertComName.find("/");
                if (nPos != string::npos)
                    m_strCertComName.erase(nPos, string::npos);
                transform(begin(m_strCertComName), end(m_strCertComName), begin(m_strCertComName), ::tolower);
            }
        }

        return 1;
    }

    void SslServerContext::AddVirtualHost(vector<shared_ptr<SslServerContext>>* pSslCtx)
    {
        SSL_CTX_set_tlsext_servername_arg(m_ctx, (void*)pSslCtx);
    }

    bool SslServerContext::SetDhParamFile(const char* const szDhParamFile)
    {
        fstream fin(szDhParamFile, ios::in | ios::binary);
        if (fin.is_open() == true)
        {
            fin.seekg(0, ios::end);
            streamoff nFileSize = fin.tellg();
            fin.seekg(0, ios::beg);

            auto pFileBuf = make_unique<char[]>(static_cast<size_t>(nFileSize));
            fin.read(pFileBuf.get(), nFileSize);
            fin.close();

            BIO* rbio = BIO_new(BIO_s_mem());
            BIO_write(rbio, pFileBuf.get(), static_cast<int>(nFileSize));

            DH* pDhParam = PEM_read_bio_DHparams(rbio, nullptr, nullptr, nullptr);
            BIO_free(rbio);

            if (SSL_CTX_set_tmp_dh(m_ctx, pDhParam) == 1)
                return true;
        }

        return false;
    }

    int SslServerContext::ALPN_CB(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
    {
        static vector<string> vProtos = { { "h2" },{ "h2-16" },{ "h2-15" },{ "h2-14" },{ "http/1.1" } };

        for (auto& strProt : vProtos)
        {
            basic_string<unsigned char> strTmp(begin(strProt), end(strProt));

            for (unsigned int i = 0; i < inlen; ++i)
            {
                int nLen = *in++;
                basic_string<unsigned char> strProtokoll(in, nLen);
                transform(begin(strProtokoll), end(strProtokoll), begin(strProtokoll), ::tolower);

                if (strProtokoll.compare(strTmp) == 0)
                {
                    *out = in, *outlen = nLen;
                    return 0;
                }
                in += nLen;
            }
        }

        return 1;
    }
    /*
    int SslServerContext::NPN_CB(SSL *ssl, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
    {
        vector<string> vProtos = { { "h2" },{ "h2-16" },{ "h2-15" },{ "h2-14" },{ "http/1.1" } };

        for (auto& strProt : vProtos)
        {
            basic_string<unsigned char> strTmp(begin(strProt), end(strProt));

            for (unsigned int i = 0; i < inlen; ++i)
            {
                int nLen = *in++;
                basic_string<unsigned char> strProtokoll(in, nLen);
                transform(begin(strProtokoll), end(strProtokoll), begin(strProtokoll), ::tolower);

                if (strProtokoll.compare(strTmp) == 0)
                {
                    *out = (unsigned char*)in, *outlen = nLen;
                    return 0;
                }
                in += nLen;
            }
        }

        return 1;
    }
    */
    int SslServerContext::SNI_CB(SSL *ssl, char iCmd, void* arg)
    {
        vector<shared_ptr<SslServerContext>>* pSslCtx = (vector<shared_ptr<SslServerContext>>*)arg;

        const char* szHostName = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

        if (pSslCtx != nullptr && szHostName != nullptr)
        {
            string strHostName(szHostName);
            transform(begin(strHostName), end(strHostName), begin(strHostName), ::tolower);

            for (auto& it : *pSslCtx)
            {
                if (it->m_strCertComName.compare(strHostName) == 0)
                {
                    SSL_set_SSL_CTX(ssl, (*it)());
                    return SSL_TLSEXT_ERR_OK;
                }
            }
        }

        return SSL_TLSEXT_ERR_NOACK;
    }


    SslConnetion::SslConnetion(SslContext* ctx, const char* szName/* = 0*/) : m_ssl(SSL_new((*ctx)())), m_iShutDownFlag(INT32_MAX), m_iWantState(0), m_szName(szName)
    {
        m_rbio = BIO_new(BIO_s_mem());
        m_wbio = BIO_new(BIO_s_mem());
        BIO_set_mem_eof_return(m_rbio, -1);
        BIO_set_mem_eof_return(m_wbio, -1);
        BIO_set_nbio(m_rbio, 1);    // make the bio non blocking
        BIO_set_nbio(m_wbio, 1);    // make the bio non blocking
        SSL_set_bio(m_ssl, m_wbio, m_rbio);

        //BIO_set_callback_arg(m_rbio, (char*)this);
        //BIO_set_callback_arg(m_wbio, (char*)this);
        //BIO_set_callback(m_rbio, CbBioInfo);
        //BIO_set_callback(m_wbio, CbBioInfo);
    }

    SslConnetion::~SslConnetion()
    {
        if (nullptr != m_ssl)
            SSL_free(m_ssl);
    }
    /*
    long SslConnetion::CbBioInfo(struct bio_st* pBioInfo, int iInt1, const char* cpBuf, int iInt2, long l1, long lRet)
    {
        SslConnetion* pThis = reinterpret_cast<SslConnetion*>(pBioInfo->cb_arg);

        return lRet;
    }
    */
    SSL* SslConnetion::operator() ()
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");
        return m_ssl;
    }

    void SslConnetion::SetErrorCb(function<void()> fError)
    {
        m_fError = fError;
    }

    uint32_t SslConnetion::SslGetOutDataSize()
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        uint32_t nTmp = BIO_ctrl(m_rbio, BIO_CTRL_PENDING, 0, NULL);
        return nTmp;
    }
    /*
    size_t SslConnetion::SslGetOutwDataSize()
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        return BIO_ctrl_pending(m_wbio);
    }

    size_t SslConnetion::SslGetInrDataSize()
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        return BIO_ctrl_wpending(m_rbio);
    }

    size_t SslConnetion::SslGetInwDataSize()
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        return BIO_ctrl_wpending(m_wbio);
    }
    */
    uint32_t SslConnetion::SslGetOutData(uint8_t* szBuffer, uint32_t nBufLen)
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        m_iWantState = 0;
        return BIO_read(m_rbio, szBuffer, nBufLen);
    }

    uint32_t SslConnetion::SslPutInData(uint8_t* szBuffer, uint32_t nWriteLen)
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        m_iWantState = 0;
        return BIO_write(m_wbio, szBuffer, nWriteLen);
    }

    bool SslConnetion::HandShakeComplet()
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        if (false == SSL_is_init_finished(m_ssl))
        {
            if (m_iWantState != 0)
                return false;

            int iRet = SSL_do_handshake(m_ssl);

            if (iRet <= 0)
            {
                int iRet2 = SSL_get_error(m_ssl, iRet);

                switch (iRet2)
                {
                case SSL_ERROR_WANT_READ:
                    m_iWantState = 1; break;
                case SSL_ERROR_WANT_WRITE:
                    m_iWantState = 2; break;
                case SSL_ERROR_ZERO_RETURN:
                    ShutDownConnection();
#ifdef _DEBUG
                    //if (m_szName)
                    //    wcout << m_szName << ": received close notify" << endl;
#endif
                    break;
                default:
                    m_iShutDownFlag = 1;
                    if (m_fError != nullptr)
                        m_fError();
#ifdef _DEBUG
                    //if (m_szName)
                    //    wcout << m_szName << ": error after SSL_do_handshake: " << iRet << endl;
#endif
                }

                return false;
            }
        }

        return true;
    }

    int SslConnetion::GetShutDownFlag()
    {
        return m_iShutDownFlag;
    }

    uint32_t SslConnetion::SslRead(uint8_t* szBuffer, uint32_t nBufLen)
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        int iRead = SSL_read(m_ssl, szBuffer, nBufLen);
        if (iRead <= 0)
        {
            iRead = SSL_get_error(m_ssl, iRead);

            switch (iRead)
            {
            case SSL_ERROR_WANT_READ:
                m_iWantState = 1; break;
            case SSL_ERROR_WANT_WRITE:
                m_iWantState = 2; break;
            case SSL_ERROR_ZERO_RETURN:
                ShutDownConnection();
#ifdef _DEBUG
                //if (m_szName)
                //    wcout << m_szName << ": received close notify" << endl;
#endif
                break;
            default:
                m_iShutDownFlag = 1;
                if (m_fError != nullptr)
                    m_fError();
#ifdef _DEBUG
                //if (m_szName)
                //    wcout << m_szName << ": error after SSL_read: " << iRead << endl;
#endif
            }

            return 0;
        }

        return iRead;
    }

    size_t SslConnetion::SslWrite(uint8_t* szBuffer, uint32_t nWriteLen)
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        int iRet = SSL_write(m_ssl, szBuffer, nWriteLen);
        if (iRet <= 0)
        {
            iRet = SSL_get_error(m_ssl, iRet);

            switch (iRet)
            {
            case SSL_ERROR_WANT_READ:
                m_iWantState = 1; break;
            case SSL_ERROR_WANT_WRITE:
                m_iWantState = 2; break;
            case SSL_ERROR_ZERO_RETURN:
                ShutDownConnection();
#ifdef _DEBUG
                //if (m_szName)
                //    wcout << m_szName << ": received close notify" << endl;
#endif
                break;
            default:
                m_iShutDownFlag = 1;
                if (m_fError != nullptr)
                    m_fError();
#ifdef _DEBUG
                //if (m_szName)
                //    wcout << m_szName << ": error after SSL_write: " << iRet << endl;
#endif
            }

            return 0;
        }

        return iRet;
    }

    int SslConnetion::ShutDownConnection()
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        m_iShutDownFlag = SSL_shutdown(m_ssl);
        return m_iShutDownFlag;
    }

    void SslConnetion::SetAlpnProtokollNames(vector<string> vProtoList)
    {
        if (vProtoList.size() > 0)
        {
            vector<unsigned char> proto_list;
            for (const auto &proto : vProtoList)
            {
                proto_list.push_back(static_cast<char>(proto.size()));
                copy_n(proto.c_str(), proto.size(), back_inserter(proto_list));
            }
            SSL_set_alpn_protos(m_ssl, proto_list.data(), static_cast<int>(proto_list.size()));
        }
    }

    string SslConnetion::GetSelAlpnProtocol()
    {
        const unsigned char* cpAlpnProto = nullptr;
        unsigned int iProtoLen = 0;
        SSL_get0_alpn_selected(m_ssl, &cpAlpnProto, &iProtoLen);
        if (cpAlpnProto != nullptr && iProtoLen > 0)
        {
            basic_string<unsigned char> strProto(cpAlpnProto, iProtoLen);
            return string(begin(strProto), end(strProto));
        }

        return string();
    }

    void SslConnetion::SetTrustedRootCertificates(const char* szFileName)
    {
        SSL_CTX_load_verify_locations(m_ssl->ctx, szFileName, nullptr);
    }

    long SslConnetion::CheckServerCertificate(const char* szHostName)
    {
        // Check 1, is a certificate present
        string strComName;
        X509* cert = SSL_get_peer_certificate(m_ssl);
        if (cert)
        {
            char caBuf[256];
            X509_NAME_oneline(X509_get_subject_name(cert), caBuf, 256);
            X509_free(cert);

            strComName = caBuf;
            size_t nPos = strComName.find("/CN=");
            if (nPos != string::npos)
            {
                strComName.erase(0, nPos + 4);
                nPos = strComName.find("/");
                if (nPos != string::npos)
                    strComName.erase(nPos, string::npos);
            }
        } /* Free immediately */

        // Check 2, is it verified?
        long lResult = SSL_get_verify_result(m_ssl);

        // Check 3, compare common name
        if (strComName.compare(szHostName) != 0 && lResult == X509_V_OK)
            lResult = X509_V_ERR_HOSTNAME_MISMATCH;
        return lResult;
    }

}