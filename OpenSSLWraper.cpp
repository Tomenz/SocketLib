/* Copyright (C) 2016-2020 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
*/

#ifndef WITHOUT_OPENSSL

#include <memory>
#include <mutex>
#include <vector>
#include <iterator>
#include <algorithm>
#include <functional>
#include <fstream>
#include <regex>

#define _WINSOCKAPI_
#include "OpenSSLWraper.h"

#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#if defined (_WIN32) || defined (_WIN64)
#include <Ws2tcpip.h>
#else   // Linux
#include <netdb.h>
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#define ASN1_STRING_get0_data(x) ASN1_STRING_data(x)
#endif

#include <string>
#include <locale>
#include <iomanip>
#include <codecvt>
#include <fcntl.h>
#include <unistd.h>
extern void OutputDebugString(const wchar_t* pOut);
extern void OutputDebugStringA(const char* pOut);
#endif  // Linux

#define WHERE_INFO(ssl, w, flag, msg) { if (w & flag) /*wcout << "\t" << msg << "  - " << SSL_state_string(ssl) << "  - " << SSL_state_string_long(ssl) << endl*/; }

namespace OpenSSLWrapper
{
    // Initialize the OpenSSL Library
    const InitOpenSSL* OpenSSLInit = InitOpenSSL::GetInstance();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    unique_ptr<mutex[]> InitOpenSSL::m_pmutLocks;
#endif
    const InitOpenSSL* InitOpenSSL::GetInstance()
    {
        static InitOpenSSL iniOpenSsl;
        return &iniOpenSsl;
    }

    InitOpenSSL::~InitOpenSSL()
    {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
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
#endif
    }

    InitOpenSSL::InitOpenSSL()
    {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_library_init();
        SSL_load_error_strings();
        strVersion = SSLeay_version(SSLEAY_VERSION);
#else
        strVersion = OpenSSL_version(OPENSSL_VERSION);
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ERR_load_BIO_strings();
        OpenSSL_add_all_algorithms();

        m_pmutLocks = make_unique<mutex[]>(CRYPTO_num_locks());
        CRYPTO_set_locking_callback(CbLocking);
#endif
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    void InitOpenSSL::CbLocking(int iMode, int iType, const char*, int iLine)
    {
        if (iMode & CRYPTO_LOCK)
            m_pmutLocks[iType].lock();
        else
            m_pmutLocks[iType].unlock();
    }
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    bool GetCertInformation(const X509* cert, string& strCommonName, vector<string>& vstrAltNames)
    {
        string caBuf(256, 0);
        X509_NAME_oneline(X509_get_subject_name(cert), &caBuf[0], static_cast<int>(caBuf.size()));

        strCommonName = &caBuf[0];
        size_t nPos = strCommonName.find("/CN=");
        if (nPos != string::npos)
        {
            strCommonName.erase(0, nPos + 4);
            nPos = strCommonName.find("/");
            if (nPos != string::npos)
                strCommonName.erase(nPos, string::npos);
            transform(begin(strCommonName), end(strCommonName), begin(strCommonName), [](char c) noexcept { return static_cast<char>(::tolower(c)); });

            if (strCommonName[0] == '*' && strCommonName[1] == '.')
                strCommonName = "^(.+\\.)?" + strCommonName.substr(2) + "$";
        }

        STACK_OF(GENERAL_NAME)* pSubAltNames = static_cast<STACK_OF(GENERAL_NAME)*>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
        if (pSubAltNames != nullptr)
        {
            const int iCountNames = sk_GENERAL_NAME_num(pSubAltNames);
            for (int i = 0; i < iCountNames; ++i)
            {
                const GENERAL_NAME* entry = sk_GENERAL_NAME_value(pSubAltNames, i);
                if (!entry) continue;

                if (entry->type == GEN_DNS)
                {
                    unsigned char* utf8 = nullptr;
                    ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);

                    string strTmp(reinterpret_cast<char*>(utf8));
                    transform(begin(strTmp), end(strTmp), begin(strTmp), [](char c) noexcept { return static_cast<char>(::tolower(c)); });
                    if (strCommonName.compare(strTmp) != 0)
                    {
                        if (strTmp[0] == '*' && strTmp[1] == '.')
                            strTmp = "^(.+\\.)?" + strTmp.substr(2) + "$";
                        vstrAltNames.push_back(strTmp);
                    }
                    if (utf8)
                        OPENSSL_free(utf8);
                }
                else if (entry->type == GEN_IPADD)
                {
                    const uint8_t* szIp = ASN1_STRING_get0_data(entry->d.iPAddress);
                    const int iStrLen = ASN1_STRING_length(entry->d.iPAddress);
                    if (szIp != nullptr)
                    {
                        struct sockaddr_storage addr;
                        addr.ss_family = iStrLen > 4 ? AF_INET6 : AF_INET;
                        if (iStrLen > 4)
                            copy(&szIp[0], &szIp[iStrLen], reinterpret_cast<uint8_t*>(&addr.__ss_align));
                        else
                            copy(&szIp[0], &szIp[iStrLen], reinterpret_cast<uint8_t*>(&addr.ss_family) + 4);
                        string caAddrClient(INET6_ADDRSTRLEN + 1, 0);
                        string servInfoClient(NI_MAXSERV, 0);
                        if (::getnameinfo(reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr_storage), &caAddrClient[0], sizeof(caAddrClient), &servInfoClient[0], NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV) == 0)
                        {
                            string strTmp(&caAddrClient[0]);
                            transform(begin(strTmp), end(strTmp), begin(strTmp), [](char c) noexcept { return static_cast<char>(::tolower(c)); });
                            if (strCommonName.compare(strTmp) != 0)
                                vstrAltNames.push_back(strTmp);
                        }
                    }
                }
            }

            sk_GENERAL_NAME_pop_free(pSubAltNames, GENERAL_NAME_free);
        }

        return true;
    }

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    SslContext::SslContext(const SSL_METHOD* sslMethod) noexcept : m_ctx(SSL_CTX_new(sslMethod))
    {
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

    int SslContext::SetCertificates(const char* szHostCertificate, const char* szHostKey)
    {
        if (szHostCertificate == nullptr || szHostKey == nullptr)
            return 0;

        if (SSL_CTX_use_certificate_file(m_ctx, szHostCertificate, SSL_FILETYPE_PEM) != 1)
            return -2;//throw runtime_error("error loading host certificate");

        if (SSL_CTX_use_PrivateKey_file(m_ctx, szHostKey, SSL_FILETYPE_PEM) != 1)
            return -3;//throw runtime_error("error loading certificate key");

        if (SSL_CTX_check_private_key(m_ctx) != 1)
            return -4;//throw runtime_error("error key not matching certificate");

        const X509 *cert = SSL_CTX_get0_certificate(m_ctx);
        if (cert)
        {
            GetCertInformation(cert, m_strCertComName, m_vstrAltNames);
            return 1;
        }
        return -5;
    }

    string& SslContext::GetCertCommonName() noexcept
    {
        return m_strCertComName;
    }

#ifdef _DEBUG
    void SslContext::SSLInfo(const SSL *ssl, int type, int val) noexcept
    {
        if (val == 0)
        {
            //wcout << "ssl error occurred." << endl;
            return;
        }

        //WHERE_INFO(ssl, type, SSL_CB_LOOP, "LOOP");
        //WHERE_INFO(ssl, type, SSL_CB_EXIT, "EXIT");
        //WHERE_INFO(ssl, type, SSL_CB_READ, "READ");
        //WHERE_INFO(ssl, type, SSL_CB_WRITE, "WRITE");
        //WHERE_INFO(ssl, type, SSL_CB_ALERT, "ALERT");
        //WHERE_INFO(ssl, type, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");

    }

    void SslContext::SSLMsgCB(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) noexcept
    {
        //wcout << "\tMessage callback with length: " << len << endl;
    }
#endif


    SslClientContext::SslClientContext() noexcept : SslContext(SSLv23_client_method())
    {
        SSL_CTX_set_options(m_ctx, (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
        SSL_CTX_set_mode(m_ctx, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_mode(m_ctx, SSL_MODE_RELEASE_BUFFERS);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_CTX_set_ecdh_auto(m_ctx, 1);
#endif
        SSL_CTX_set_cipher_list(m_ctx, "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4");
    }

    void SslClientContext::SetAlpnProtokollNames(const vector<string>& vProtoList)
    {
        if (vProtoList.size() > 0)
        {
            vector<unsigned char> proto_list;
            for (const auto &proto : vProtoList)
            {
                proto_list.push_back(static_cast<char>(proto.size()));
                copy_n(proto.c_str(), proto.size(), back_inserter(proto_list));
            }
            SSL_CTX_set_alpn_protos(m_ctx, proto_list.data(), static_cast<unsigned int>(proto_list.size()));
        }
    }

    void SslClientContext::SetTrustedRootCertificates(const char* szTrustRootCert) noexcept
    {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        SSL_CTX_load_verify_locations(m_ctx, szTrustRootCert, nullptr);
#else
        SSL_CTX_load_verify_file(m_ctx, szTrustRootCert);
#endif
    }


    SslServerContext::SslServerContext() noexcept : SslContext(SSLv23_server_method())
    {
        //SSL_CTX_set_options(m_ctx, (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
        SSL_CTX_set_options(m_ctx, (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) | /*SSL_OP_NO_RENEGOTIATION |*/ SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
        SSL_CTX_set_mode(m_ctx, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_mode(m_ctx, SSL_MODE_RELEASE_BUFFERS);
        SSL_CTX_set_mode(m_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
        SSL_CTX_set_verify(m_ctx, SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set_mode(m_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_CTX_set_ecdh_auto(m_ctx, 1);
#endif
        SSL_CTX_set_dh_auto(m_ctx, 1);

        //https://raymii.org/s/tutorials/Strong_SSL_Security_On_Apache2.html
//        SSL_CTX_set_cipher_list(m_ctx, "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4");
        SSL_CTX_set_cipher_list(m_ctx, "EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA:EECDH:EDH+AESGCM:EDH:+3DES:ECDH+AESGCM:ECDH+AES:ECDH:AES:HIGH:MEDIUM:!RC4:!CAMELLIA:!SEED:!aNULL:!MD5:!eNULL:!LOW:!EXP:!DSS:!PSK:!SRP");

#if OPENSSL_VERSION_NUMBER > 0x10101000L
        SSL_CTX_set_ciphersuites(m_ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");  //https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_cipher_list.html
#endif
        //SSL_CTX_set_session_id_context(m_ctx, reinterpret_cast<unsigned char*>(this), sizeof(void*));

        //SSL_CTX_set_alpn_select_cb(m_ctx, ALPN_CB, this);
        //SSL_CTX_set_next_proto_select_cb(m_ctx, NPN_CB, 0);
        SSL_CTX_set_tlsext_servername_arg(m_ctx, nullptr);
        SSL_CTX_set_tlsext_servername_callback(m_ctx, SNI_CB);
    }

    int SslServerContext::SetCertificates(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey)
    {
        if (szCAcertificate != nullptr && SSL_CTX_use_certificate_chain_file(m_ctx, szCAcertificate) != 1)
            return -1;// throw runtime_error("error loading CA root certificate");

        return SslContext::SetCertificates(szHostCertificate, szHostKey);
    }

    void SslServerContext::AddVirtualHost(vector<SslServerContext>* pSslCtx) noexcept
    {
        SSL_CTX_set_tlsext_servername_arg(m_ctx, reinterpret_cast<void*>(pSslCtx));
    }

    bool SslServerContext::SetDhParamFile([[maybe_unused]] const char* const szDhParamFile)
    {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        fstream fin(szDhParamFile, ios::in | ios::binary);
        if (fin.is_open() == true)
        {
            fin.seekg(0, ios::end);
            const streamoff nFileSize = fin.tellg();
            fin.seekg(0, ios::beg);

            auto pFileBuf = vector<char>(nFileSize);
            fin.read(&pFileBuf[0], nFileSize);
            fin.close();

            BIO* rbio = BIO_new(BIO_s_mem());
            BIO_write(rbio, &pFileBuf[0], static_cast<int>(nFileSize));

            DH* pDhParam = PEM_read_bio_DHparams(rbio, nullptr, nullptr, nullptr);
            BIO_free(rbio);

            if (SSL_CTX_set_tmp_dh(m_ctx, pDhParam) == 1)
                return true;
        }

        return false;
#else
        return true;
#endif
    }

    bool SslServerContext::SetCipher(const char* const szCipher) noexcept
    {
        return SSL_CTX_set_cipher_list(m_ctx, szCipher) == 1 ? true : false;
    }

    void SslServerContext::SetAlpnProtokollNames(const vector<string>& vStrList)
    {
        m_vstrAlpnProtoList = vStrList;
        SSL_CTX_set_alpn_select_cb(m_ctx, ALPN_CB, this);
    }

    int SslServerContext::ALPN_CB(SSL* /*ssl*/, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
    {
        SslServerContext* pSslCtx = static_cast<SslServerContext*>(arg);
        if (pSslCtx == nullptr || in == nullptr || out == nullptr)
            return 1;

        for (auto& strProt : pSslCtx->m_vstrAlpnProtoList)
        {
            const uint8_t* inTmp = in;
            for (unsigned int i = 0; i < inlen;)
            {
                uint8_t nLen = *inTmp++;
                string strProtokoll(reinterpret_cast<const char*>(inTmp), static_cast<size_t>(nLen));
                transform(begin(strProtokoll), end(strProtokoll), begin(strProtokoll), [](char c) noexcept { return static_cast<char>(::tolower(c)); });

                if (strProtokoll == strProt)
                {
                    *out = inTmp, *outlen = nLen;
                    return 0;
                }
                inTmp += nLen;
                i += nLen + 1;
            }
        }

        return 1;
    }
    /*
    int SslServerContext::NPN_CB(SSL *ssl, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
    {
        vector<string> vProtos{ { "h2" },{ "h2-16" },{ "h2-15" },{ "h2-14" },{ "http/1.1" } };

        for (auto& strProt : vProtos)
        {
            for (unsigned int i = 0; i < inlen; ++i)
            {
                int nLen = *in++;
                basic_string<unsigned char> strProtokoll(reinterpret_cast<const char*>(in), nLen);
                transform(begin(strProtokoll), end(strProtokoll), begin(strProtokoll), ::tolower);

                if (strProtokoll == strProt)
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
    int SslServerContext::SNI_CB(SSL* ssl, char /*iCmd*/, void* arg)
    {
        vector<SslServerContext>* pSslCtx = static_cast<vector<SslServerContext>*>(arg);

        const char* szHostName = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

        if (szHostName == nullptr)  // if the host name is not set, the connection was made by IP address, we use the IP of the interface the connection came in, to find the certificate
        {
            const string& (*fnForwarder)(void*) = reinterpret_cast<const string&(*)(void*)>(SSL_get_ex_data(ssl, 0));   // Index 0 = Funktion pointer to a static proxy function
            void* Obj = SSL_get_ex_data(ssl, 1);    // Index 1 is the "this" pointer of the SslTcpSocket how owns the ssl object
            if (fnForwarder != nullptr && Obj != nullptr)
                szHostName = fnForwarder(Obj).c_str(); // We get the IP address of the Interface the connection come in
        }

        if (pSslCtx != nullptr && szHostName != nullptr)
        {
            string strHostName(szHostName);
            transform(begin(strHostName), end(strHostName), begin(strHostName), [](char c) noexcept { return static_cast<char>(::tolower(c)); });

            function<bool(string&)> fnDomainCompare = [strHostName](string& it) -> bool
            {
                if (it[0] == '^')   // we have a regular expression
                    return regex_match(strHostName, regex(it));
                else
                    return it.compare(strHostName) == 0 ? true : false;
            };

            for (auto& it : *pSslCtx)
            {
                if ((it.m_strCertComName[0] == '^' && regex_match(strHostName, regex(it.m_strCertComName))) || it.m_strCertComName == strHostName || find_if(begin(it.m_vstrAltNames), end(it.m_vstrAltNames), fnDomainCompare) != end(it.m_vstrAltNames))
                {
                    SSL_set_SSL_CTX(ssl, it());
                    return SSL_TLSEXT_ERR_OK;
                }
            }
        }

        return SSL_TLSEXT_ERR_NOACK;
    }

    SslUdpContext::SslUdpContext() noexcept : SslContext(DTLS_method())
    {
        SSL_CTX_set_options(m_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
        SSL_CTX_set_mode(m_ctx, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_mode(m_ctx, SSL_MODE_RELEASE_BUFFERS);
        SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, verify_callback);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_CTX_set_ecdh_auto(m_ctx, 1);
#endif
        SSL_CTX_set_cipher_list(m_ctx, "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4");
    }

    int SslUdpContext::verify_callback(int /*preverify_ok*/, X509_STORE_CTX* /*ctx*/) noexcept
    {
        return 1;
    }


    SslConnection::SslConnection(SslContext& ctx) : m_ssl(SSL_new(ctx())), m_iShutDownFlag(INT32_MIN), m_bZeroReceived(false), m_iWantState(0)
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

    SslConnection::~SslConnection()
    {
        if (nullptr != m_ssl)
            SSL_free(m_ssl);
    }

    /*
    long SslConnection::CbBioInfo(struct bio_st* pBioInfo, int iInt1, const char* cpBuf, int iInt2, long l1, long lRet)
    {
        SslConnection* pThis = reinterpret_cast<SslConnection*>(pBioInfo->cb_arg);

        return lRet;
    }
    */
    SSL* SslConnection::operator() ()
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");
        return m_ssl;
    }

    void SslConnection::SetErrorCb(const function<void()>& fError)
    {
        m_fError = fError;
    }

    void SslConnection::SetUserData(int iIndex, void* pVoid) noexcept
    {
        SSL_set_ex_data(m_ssl, iIndex, pVoid);
    }

    void SslConnection::SSLSetAcceptState()
    {
        lock_guard<mutex> lk(m_mxSsl);
        SSL_set_accept_state(m_ssl);
    }

    void SslConnection::SSLSetConnectState()
    {
        lock_guard<mutex> lk(m_mxSsl);
        SSL_set_connect_state(m_ssl);
    }

    int SslConnection::SSLDoHandshake()
    {
        lock_guard<mutex> lk(m_mxSsl);
        return SSL_do_handshake(m_ssl);
    }

    int SslConnection::SslInitFinished()
    {
        lock_guard<mutex> lk(m_mxSsl);
        return SSL_is_init_finished(m_ssl);
    }

    void SslConnection::SSLSetShutdown(int iState)
    {
        lock_guard<mutex> lk(m_mxSsl);
        SSL_set_shutdown(m_ssl, iState);
    }

    int SslConnection::SSLGetShutdown()
    {
        lock_guard<mutex> lk(m_mxSsl);
        return SSL_get_shutdown(m_ssl);
    }

    int SslConnection::SSLGetError(int iResult)
    {
        lock_guard<mutex> lk(m_mxSsl);
        return SSL_get_error(m_ssl, iResult);
    }

    size_t SslConnection::SslGetOutDataSize()
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        return BIO_ctrl_pending(m_rbio);
    }
    /*
    size_t SslConnection::SslGetOutwDataSize()
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        return BIO_ctrl_pending(m_wbio);
    }

    size_t SslConnection::SslGetInrDataSize()
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        return BIO_ctrl_wpending(m_rbio);
    }

    size_t SslConnection::SslGetInwDataSize()
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        return BIO_ctrl_wpending(m_wbio);
    }
    */
    size_t SslConnection::SslGetOutData(uint8_t* szBuffer, size_t nBufLen)
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        m_iWantState &= ~2;
        size_t nRead = 0;
        const int iResult = BIO_read_ex(m_rbio, szBuffer, nBufLen, &nRead);
        if (iResult <= 0)
            return 0;
        return nRead;
    }

    size_t SslConnection::SslPutInData(const uint8_t* szBuffer, size_t nWriteLen)
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        m_iWantState &= ~1;
        size_t nWritten = 0;
        const int iResult = BIO_write_ex(m_wbio, szBuffer, nWriteLen, &nWritten);
        if (iResult <= 0)
            return 0;
        BIO_flush(m_wbio);
        return nWritten;
    }

    int SslConnection::GetShutDownFlag() noexcept
    {
        return m_iShutDownFlag;
    }

    bool SslConnection:: GetZeroReceived() noexcept
    {
        return m_bZeroReceived;
    }

    size_t SslConnection::SslRead(uint8_t* szBuffer, size_t nBufLen, int* iErrorHint/* = nullptr*/)
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        //OSSL_HANDSHAKE_STATE hsState = SSL_get_state(m_ssl);
        //if (hsState != TLS_ST_OK)
        //    OutputDebugString(wstring(L"SSL invalid state: " + to_wstring(hsState) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>(m_ssl)) + L"\r\n").c_str());

        m_mxSsl.lock();

        ERR_clear_error();
        size_t nRead = 0;
        int iResult = SSL_read_ex(m_ssl, szBuffer, nBufLen, &nRead);
        if (iResult <= 0)
        {
            iResult = SSL_get_error(m_ssl, iResult);
            if (iErrorHint != nullptr)
                *iErrorHint = iResult;
            m_mxSsl.unlock();

            switch (iResult)
            {
            case SSL_ERROR_WANT_READ:
                m_iWantState |= 1; break;
            case SSL_ERROR_WANT_WRITE:
                m_iWantState |= 2; break;
            case SSL_ERROR_ZERO_RETURN:
                m_bZeroReceived = true;
                ShutDownConnection(iErrorHint);
                break;
            case SSL_ERROR_SYSCALL:
                iResult = errno;
                if (iResult == 0 && ERR_peek_error() == 0)    // if errno and ERR_peack_error are both 0, we not having really an error, and give it a other shoot
                    break;
                [[fallthrough]];
            default:
                m_iShutDownFlag = 1;
                if (m_fError)
                    m_fError();
            }

            return 0;
        }
        m_mxSsl.unlock();

        return nRead;
    }

    size_t SslConnection::SslWrite(const uint8_t* szBuffer, size_t nWriteLen, int* iErrorHint/* = nullptr*/)
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        //OSSL_HANDSHAKE_STATE hsState = SSL_get_state(m_ssl);
        //if (hsState != TLS_ST_OK)
        //    OutputDebugString(wstring(L"SSL invalid state: " + to_wstring(hsState) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>(m_ssl)) + L"\r\n").c_str());

        m_mxSsl.lock();

        ERR_clear_error();
        size_t nWritten = 0;
        int iResult = SSL_write_ex(m_ssl, szBuffer, nWriteLen, &nWritten);
        if (iResult <= 0)
        {
            iResult = SSL_get_error(m_ssl, iResult);
            if (iErrorHint != nullptr)
                *iErrorHint = iResult;
            m_mxSsl.unlock();

            switch (iResult)
            {
            case SSL_ERROR_WANT_READ:
                m_iWantState |= 1; break;
            case SSL_ERROR_WANT_WRITE:
                m_iWantState |= 2; break;
            case SSL_ERROR_ZERO_RETURN:
                m_bZeroReceived = true;
                ShutDownConnection(iErrorHint);
                break;
            case SSL_ERROR_SYSCALL:
                iResult = errno;
                [[fallthrough]];
            default:
OutputDebugStringA(string(GetSslErrAsString() + "errno = " + to_string(iResult) + "\r\n").c_str());
                m_iShutDownFlag = 1;
                if (m_fError)
                    m_fError();
            }

            return 0;
        }
        m_mxSsl.unlock();

        return nWritten;
    }

    int SslConnection::ShutDownConnection(int* iErrorHint/* = nullptr*/)
    {
        if (nullptr == m_ssl)
            throw runtime_error("Not Initialized");

        if (m_iShutDownFlag < 1)
        {
            lock_guard<mutex> lk(m_mxSsl);

            m_iShutDownFlag = SSL_shutdown(m_ssl);
            if (m_iShutDownFlag < 0)
            {
                int iError = SSL_get_error(m_ssl, m_iShutDownFlag);
                if (iErrorHint != nullptr)
                    *iErrorHint = iError;
                if (iError != SSL_ERROR_WANT_READ)
                {
                    OutputDebugString(wstring(L"SSL_shutdown code: " + to_wstring(m_iShutDownFlag) + L" Error-Code: " + to_wstring(iError) + L" on ssl context: " + to_wstring(reinterpret_cast<size_t>(m_ssl))).c_str());
                    OutputDebugStringA(string(", msg: " + GetSslErrAsString()).c_str());
                }
            }
        }
        return m_iShutDownFlag;
    }

    void SslConnection::SetAlpnProtokollNames(const vector<string>& vProtoList)
    {
        if (vProtoList.size() > 0)
        {
            vector<unsigned char> proto_list;
            for (const auto &proto : vProtoList)
            {
                proto_list.push_back(static_cast<char>(proto.size()));
                copy_n(proto.c_str(), proto.size(), back_inserter(proto_list));
            }
            SSL_set_alpn_protos(m_ssl, proto_list.data(), static_cast<unsigned int>(proto_list.size()));
        }
    }

    string SslConnection::GetSelAlpnProtocol()
    {
        const unsigned char* cpAlpnProto = nullptr;
        unsigned int iProtoLen = 0;
        SSL_get0_alpn_selected(m_ssl, &cpAlpnProto, &iProtoLen);
        if (cpAlpnProto != nullptr && iProtoLen > 0)
            return string(reinterpret_cast<const char*>(cpAlpnProto), iProtoLen);

        return string();
    }

    int SslConnection::SetTrustedRootCertificates(const char* szFileName) noexcept
    {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        return SSL_CTX_load_verify_locations(SSL_get_SSL_CTX(m_ssl), szFileName, nullptr);
#else
        return SSL_CTX_load_verify_file(SSL_get_SSL_CTX(m_ssl), szFileName);
#endif
    }

    long SslConnection::SetSniName(const char* szServerName) noexcept
    {
        return SSL_set_tlsext_host_name(m_ssl, szServerName);
    }

    long SslConnection::CheckServerCertificate(const char* szHostName)
    {
        // Check 1, is a certificate present
        string strComName;
        vector<string> vstrAltNames;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        X509* cert = SSL_get1_peer_certificate(m_ssl);
#else
        X509* cert = SSL_get_peer_certificate(m_ssl);
#endif
        if (cert)
        {
            GetCertInformation(cert, strComName, vstrAltNames);
            X509_free(cert);
        } /* Free immediately */

        // Check 2, is it verified?
        long lResult = SSL_get_verify_result(m_ssl);

        // Check 3, compare common name
        function<bool(string&)> fnDomainCompare = [szHostName](string& it) -> bool
        {
            if (it[0] == '^')   // we have a regular expression
                return regex_match(szHostName, regex(it));
            else
                return it.compare(szHostName) == 0 ? true : false;
        };

        if (strComName != szHostName && lResult == X509_V_OK && find_if(begin(vstrAltNames), end(vstrAltNames), fnDomainCompare) == end(vstrAltNames))
            lResult = X509_V_ERR_HOSTNAME_MISMATCH;
        return lResult;
    }

    string SslConnection::GetSslErrAsString()
    {
        /*BIO *bio = BIO_new(BIO_s_mem());
        ERR_print_errors(bio);
        char *buf = NULL;
        size_t len = BIO_get_mem_data(bio, &buf);
        string strTmp(buf, len);
        BIO_free(bio);*/

        string strTmp;
        uint32_t nError = ERR_get_error();
        while (nError != 0)
        {
            string buf(512, 0);
            ERR_error_string_n(nError, &buf[0], buf.size());
            strTmp += &buf[0];
            strTmp += "\r\n";
            nError = ERR_get_error();
        }
        return strTmp;
    }


}

#endif
