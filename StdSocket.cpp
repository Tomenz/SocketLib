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

#define _CRTDBG_MAP_ALLOC

#include <sstream>
#include <vector>
#include <algorithm>
#include "StdSocket.h"

#if defined (_WIN32) || defined (_WIN64)
#include <iphlpapi.h>
//https://support.microsoft.com/de-de/kb/257460
//#pragma comment(lib, "wsock32")
#pragma comment(lib, "Ws2_32")
#pragma comment(lib, "IPHLPAPI.lib")
typedef char SOCKOPT;
#else
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#define closesocket(x) close(x)
#define WSAGetLastError() errno
#define WSAEWOULDBLOCK EWOULDBLOCK
#define SD_RECEIVE SHUT_RD
#define SD_SEND SHUT_WR
#define SD_BOTH SHUT_RDWR
typedef int SOCKOPT;
#endif

// Initialize the Socket Library
const InitSocket* SocketInit = InitSocket::GetInstance();

InitSocket* InitSocket::GetInstance()
{
    static InitSocket iniSocket;
    return &iniSocket;
}

InitSocket::~InitSocket()
{
#if defined(_WIN32) || defined(_WIN64)
    CancelMibChangeNotify2(m_hIFaceNotify);
    ::WSACleanup();
#else
    m_bStopThread = true;
    if (m_thIpChange.joinable() == true)
        m_thIpChange.join();
#endif
}

void InitSocket::SetAddrNotifyCallback(function<void(bool, const string&, int, int)> fnCbAddrNotify)
{
    m_fnCbAddrNotify = fnCbAddrNotify;
    if (m_fnCbAddrNotify)
    {   // notify on current ip addresses
        for (auto iter : m_vCurIPAddr)
            m_fnCbAddrNotify(true, get<0>(iter), get<1>(iter), get<2>(iter));
    }
}

InitSocket::InitSocket()
{
#if defined(_WIN32) || defined(_WIN64)
    WSADATA wsaData;
    ::WSAStartup(MAKEWORD(2, 2), &wsaData);
    NotifyIpInterfaceChange(AF_UNSPEC, IpIfaceChanged, this, TRUE, &m_hIFaceNotify);
#else
    //signal(SIGPIPE, SIG_IGN);
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGPIPE);
    sigprocmask(SIG_BLOCK, &sigset, NULL);
    BaseSocket::EnumIpAddresses(bind(&InitSocket::CbEnumIpAdressen, this, placeholders::_1, placeholders::_2, placeholders::_3, placeholders::_4), &m_vCurIPAddr);
    m_bStopThread = false;
    m_thIpChange = thread(&InitSocket::IpChangeThread, this);
#endif
}

#if defined (_WIN32) || defined (_WIN64)
VOID __stdcall InitSocket::IpIfaceChanged(PVOID CallerContext, PMIB_IPINTERFACE_ROW pRow, MIB_NOTIFICATION_TYPE NotificationType)
{
    InitSocket* pThis = static_cast<InitSocket*>(CallerContext);

    function<int(int, const string&, int, void*)> fnCb = bind(&InitSocket::CbEnumIpAdressen, pThis, placeholders::_1, placeholders::_2, placeholders::_3, placeholders::_4);
    vector<tuple<string, int, int>> vNewIPAddr;
    BaseSocket::EnumIpAddresses(fnCb, &vNewIPAddr);
    pThis->NotifyOnAddressChanges(vNewIPAddr);

    switch (NotificationType)
    {
    case MibParameterNotification:  // 0
        OutputDebugString(L"IP Parameter changed\r\n");
        break;
    case MibAddInstance:            // 1
        OutputDebugString(L"IP Interface added\r\n");
        break;
    case MibDeleteInstance:         // 2
        OutputDebugString(L"IP Interface removed\r\n");
        break;
    case MibInitialNotification:    // 3
        OutputDebugString(L"IP Notification initialized\r\n");
        break;
    }

}
#else
void InitSocket::IpChangeThread()
{
    SOCKET fSock;
    if ((fSock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
    {
        return;
    }

    struct sockaddr_nl addr = { 0 };
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    if (bind(fSock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        ::closesocket(fSock);
        return;
    }

    if (fcntl(fSock, F_SETFD, FD_CLOEXEC) == -1 || fcntl(fSock, F_SETFL, fcntl(fSock, F_GETFL) | O_NONBLOCK) == -1)
    {
        ::closesocket(fSock);
        return;
    }

    while (m_bStopThread == false)
    {
        fd_set readfd, errorfd;
        struct timeval timeout;

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        FD_ZERO(&readfd);
        FD_ZERO(&errorfd);

        FD_SET(fSock, &readfd);
        FD_SET(fSock, &errorfd);

        if (::select(static_cast<int>(fSock + 1), &readfd, nullptr, &errorfd, &timeout) > 0)
        {
            if (FD_ISSET(fSock, &errorfd))
            {
                int iError;
                socklen_t iLen = sizeof(iError);
                getsockopt(fSock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&iError), &iLen);
                break;
            }

            if (FD_ISSET(fSock, &readfd))
            {
                char buf[4096];
                int32_t transferred = ::recv(fSock, buf, sizeof(buf), 0);

                if (transferred > 0)
                {
                    struct nlmsghdr* nlh = reinterpret_cast<struct nlmsghdr*>(buf);
                    while ((NLMSG_OK(nlh, transferred)) && (nlh->nlmsg_type != NLMSG_DONE))
                    {
                        if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR || nlh->nlmsg_type == RTM_GETADDR)
                        {
                            /*struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nlh);
                            struct rtattr *rth = IFA_RTA(ifa);
                            int rtl = IFA_PAYLOAD(nlh);

                            char name[IFNAMSIZ];
                            if_indextoname(ifa->ifa_index, name);
                            */
                            vector<tuple<string, int, int>> vNewIPAddr;
                            BaseSocket::EnumIpAddresses(bind(&InitSocket::CbEnumIpAdressen, this, placeholders::_1, placeholders::_2, placeholders::_3, placeholders::_4), &vNewIPAddr);
                            NotifyOnAddressChanges(vNewIPAddr);
                        }
                        nlh = NLMSG_NEXT(nlh, transferred);
                    }
                }
            }
        }
    }

    ::closesocket(fSock);
}
#endif

int InitSocket::CbEnumIpAdressen(int iFamiely, const string& strIp, int nInterFaceId, void* vpUserParam)
{
    if (vpUserParam == nullptr)
        return 1;   // Stop enumeration, doesn't make sense

    vector<tuple<const string, int, int>>* pmaStrIps = reinterpret_cast<vector<tuple<const string, int, int>>*>(vpUserParam);
    pmaStrIps->push_back(make_tuple(strIp, iFamiely, nInterFaceId));
    return 0;
}

void InitSocket::NotifyOnAddressChanges(vector<tuple<string, int, int>>& vNewListing)
{
    vector<tuple<string, int, int>> vDelIPAddr;

    m_mxCurIpAddr.lock();
    // remove all IP addr. in the vector that where before available
    for (auto iter = begin(m_vCurIPAddr); iter != end(m_vCurIPAddr);)
    {
        auto itFound = find_if(begin(vNewListing), end(vNewListing), [iter](auto& item) { return get<0>(*iter) == get<0>(item) ? true : false; });
        if (itFound != end(vNewListing))
            vNewListing.erase(itFound);  // address existed before, so remove it from the list with our new addresses
        else
        {   // the IP does not exist any more
            vDelIPAddr.push_back(*iter);    // remember witch one was removed
            iter = m_vCurIPAddr.erase(iter);
            continue;
        }
        ++iter;
    }

    for (auto iter : vNewListing)
        m_vCurIPAddr.push_back(iter);    // remember witch one was removed

    m_mxCurIpAddr.unlock();

    if (m_fnCbAddrNotify)
    {
        // Notify on all deleted IP addresses
        for (auto iter : vDelIPAddr)
            m_fnCbAddrNotify(false, get<0>(iter), get<1>(iter), get<2>(iter));
        // Notify on all new IP addresses
        for (auto iter : vNewListing)
            m_fnCbAddrNotify(true, get<0>(iter), get<1>(iter), get<2>(iter));
    }
}

atomic_uint BaseSocket::s_atRefCount(0);

BaseSocket::BaseSocket() : m_fSock(INVALID_SOCKET), m_bStop(false), m_iError(0), m_iShutDownState(0), m_fError(bind(&BaseSocket::OnError, this))
{
    ++s_atRefCount;
}

BaseSocket::~BaseSocket()
{
    if (m_thListen.joinable() == true)
        m_thListen.join();
    if (m_thWrite.joinable() == true)
        m_thWrite.join();

    --s_atRefCount;
}

function<void(BaseSocket*)> BaseSocket::BindErrorFunction(function<void(BaseSocket*)> fError) noexcept
{
    m_fError.swap(fError);
    return fError;
}

function<void(BaseSocket*)> BaseSocket::BindCloseFunction(function<void(BaseSocket*)> fCloseing) noexcept
{
    m_fCloseing.swap(fCloseing);
    return fCloseing;
}

void BaseSocket::SetSocketOption(const SOCKET& fd)
{
    SOCKOPT rc = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &rc, static_cast<int>(sizeof(rc))) != 0)
        throw WSAGetLastError();
#if defined(_WIN32) || defined(_WIN64)
    unsigned long rl = 1;
    if (::ioctlsocket(fd, FIONBIO, &rl) == SOCKET_ERROR)  /* 1 for non-block, 0 for block */
        throw WSAGetLastError();
#else
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)
        throw errno;
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == -1)
        throw errno;
#endif
}

void BaseSocket::OnError()
{
    Close();
}

void BaseSocket::StartCloseingCB()
{
    m_mxFnClosing.lock();
    if (m_fCloseing)
    {
        function<void(BaseSocket*)> tmpfun;
        m_fCloseing.swap(tmpfun);
        m_mxFnClosing.unlock();
        tmpfun(this);
    }
    else
        m_mxFnClosing.unlock();
}

uint16_t BaseSocket::GetSocketPort()
{
    struct sockaddr_storage addrPe;
    socklen_t addLen = sizeof(addrPe);
    if (::getsockname(m_fSock, (struct sockaddr*)&addrPe, &addLen) == 0)  // Get our IP where the connection was established
    {
        char caAddrPeer[INET6_ADDRSTRLEN + 1] = { 0 };
        char servInfoPeer[NI_MAXSERV] = { 0 };
        if (::getnameinfo((struct sockaddr*)&addrPe, sizeof(struct sockaddr_storage), caAddrPeer, sizeof(caAddrPeer), servInfoPeer, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV) == 0)
        {
            return stoi(servInfoPeer);
        }
    }

    return 0;
}

int BaseSocket::EnumIpAddresses(function<int(int, const string&, int, void*)> fnCallBack, void* vpUser)
{
#if defined(_WIN32) || defined(_WIN64)
    ULONG outBufLen = 16384;
    PIP_ADAPTER_ADDRESSES pAddressList = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(new char[outBufLen]);
    if (pAddressList == nullptr)
        return ERROR_OUTOFMEMORY;
    DWORD ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, pAddressList, &outBufLen);

    if (ret == ERROR_BUFFER_OVERFLOW)
    {
        delete reinterpret_cast<char*>(pAddressList);
        pAddressList = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(new char[outBufLen]);
        if (pAddressList == nullptr)
            return ERROR_OUTOFMEMORY;
        ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, pAddressList, &outBufLen);
    }

    if (ret == ERROR_SUCCESS)
    {
        for (PIP_ADAPTER_ADDRESSES pCurrentAddresses = pAddressList; pCurrentAddresses != nullptr; pCurrentAddresses = pCurrentAddresses->Next)
        {
            if (pCurrentAddresses->IfType == IF_TYPE_SOFTWARE_LOOPBACK || pCurrentAddresses->OperStatus != IfOperStatusUp)
                continue;

            for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrentAddresses->FirstUnicastAddress; pUnicast != nullptr; pUnicast = pUnicast->Next)
            {
                if ((pUnicast->Flags & IP_ADAPTER_ADDRESS_TRANSIENT) == IP_ADAPTER_ADDRESS_TRANSIENT)
                    continue;

                string strTmp(255, 0);
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6)
                    strTmp = inet_ntop(AF_INET6, &((struct sockaddr_in6*)pUnicast->Address.lpSockaddr)->sin6_addr, &strTmp[0], strTmp.size());
                else
                    strTmp = inet_ntop(AF_INET, &((struct sockaddr_in*)pUnicast->Address.lpSockaddr)->sin_addr, &strTmp[0], strTmp.size());
                if (fnCallBack(pUnicast->Address.lpSockaddr->sa_family, strTmp, pCurrentAddresses->IfIndex, vpUser) != 0)
                {
                    delete reinterpret_cast<char*>(pAddressList);
                    return ERROR_CANCELLED;
                }
            }
        }
    }

    delete reinterpret_cast<char*>(pAddressList);
#else
    int ret = 0;
    struct ifaddrs* lstAddr;
    if (getifaddrs(&lstAddr) == 0)
    {
        for (struct ifaddrs *ptr = lstAddr; ptr != nullptr; ptr = ptr->ifa_next)
        {
            if (ptr->ifa_addr == nullptr || (ptr->ifa_addr->sa_family != AF_INET && ptr->ifa_addr->sa_family != AF_INET6))
                continue;
            if ((ptr->ifa_flags & IFF_UP) == 0 || (ptr->ifa_flags & IFF_LOOPBACK) == IFF_LOOPBACK)
                continue;
            string strAddrBuf(NI_MAXHOST, 0);
            if (/*&& string(ptr->ifa_name).find("eth") != string::npos &&*/ getnameinfo(ptr->ifa_addr, (ptr->ifa_addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), &strAddrBuf[0], strAddrBuf.size(), NULL, 0, NI_NUMERICHOST) == 0)
            {
                unsigned int iIfIndex = if_nametoindex(ptr->ifa_name);

                if (fnCallBack(ptr->ifa_addr->sa_family, strAddrBuf, iIfIndex, vpUser) != 0)
                {
                    freeifaddrs(lstAddr);
                    return ECANCELED;
                }
            }
        }

        freeifaddrs(lstAddr);
    }
#endif
    return ret;
}

//************************************************************************************

TcpSocket::TcpSocket() : m_bCloseReq(false), m_pRefServSocket(nullptr), m_bSelfDelete(false)
{
    atomic_init(&m_atInBytes, static_cast<uint32_t>(0));
    atomic_init(&m_atOutBytes, static_cast<uint32_t>(0));
}

TcpSocket::TcpSocket(const SOCKET fSock, const TcpServer* pRefServSocket) : m_bCloseReq(false), m_pRefServSocket(pRefServSocket), m_bSelfDelete(false)
{
    m_fSock = fSock;

    atomic_init(&m_atInBytes, static_cast<uint32_t>(0));
    atomic_init(&m_atOutBytes, static_cast<uint32_t>(0));

    m_iShutDownState = 3;
    m_thWrite = thread(&TcpSocket::WriteThread, this);
}

TcpSocket::~TcpSocket()
{
    //OutputDebugString(L"TcpSocket::~TcpSocket\r\n");
    m_bStop = true; // Stops the listening thread
    m_bCloseReq = true;
    m_atOutBytes = 0;
    m_cv.notify_all();

    if (m_thConnect.joinable() == true)
        m_thConnect.join();

    if (m_fSock != INVALID_SOCKET)
    {
        ::closesocket(m_fSock);
        m_fSock = INVALID_SOCKET;

        lock_guard<mutex> lock(m_mxFnClosing);
        if (m_fCloseing)
            m_fCloseing(this);
    }
}

bool TcpSocket::Connect(const char* const szIpToWhere, const uint16_t sPort)
{
    if (m_fSock != INVALID_SOCKET)
    {
        ::closesocket(m_fSock);
        m_fSock = INVALID_SOCKET;
    }

    struct addrinfo *lstAddr, hint = { 0 };
    hint.ai_family = PF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;

    if (::getaddrinfo(szIpToWhere, to_string(sPort).c_str(), &hint, &lstAddr) != 0)
        return false;

    bool bRet = true;

    try
    {
        m_fSock = ::socket(lstAddr->ai_family, lstAddr->ai_socktype, lstAddr->ai_protocol);
        if (m_fSock == INVALID_SOCKET)
            throw WSAGetLastError();

        SetSocketOption(m_fSock);

        if (lstAddr->ai_family == AF_INET6)
        {
            uint32_t on = 0;
            if (::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&on), sizeof(on)) == -1)
                throw WSAGetLastError();
        }

        int rc = ::connect(m_fSock, lstAddr->ai_addr, static_cast<int>(lstAddr->ai_addrlen));
        if (rc == SOCKET_ERROR)
        {
            m_iError = WSAGetLastError();
#if defined (_WIN32) || defined (_WIN64)
            if (m_iError != WSAEWOULDBLOCK)
#else
            if (m_iError != EINPROGRESS)
#endif
                throw m_iError;

            m_iError = 0;
            m_thConnect = thread(&TcpSocket::ConnectThread, this);
        }
        else
        {
            GetConnectionInfo();

            m_thListen = thread(&TcpSocket::SelectThread, this);
            m_thWrite = thread(&TcpSocket::WriteThread, this);

            if (m_fClientConneted)
                m_fClientConneted(this);
        }
    }

    catch (int iSocketErr)
    {
        m_iError = iSocketErr;

        if (m_fSock != INVALID_SOCKET)
            ::closesocket(m_fSock);
        m_fSock = INVALID_SOCKET;
        bRet = false;
    }

    ::freeaddrinfo(lstAddr);

    return bRet;
}

void TcpSocket::SetSocketOption(const SOCKET& fd)
{
    BaseSocket::SetSocketOption(fd);

    SOCKOPT rc = 1;
    if (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &rc, sizeof(rc)) == -1)
        throw WSAGetLastError();
}

uint32_t TcpSocket::Read(void* buf, uint32_t len)
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
    copy(BUFFER(data).get(), BUFFER(data).get() + nToCopy, &static_cast<uint8_t*>(buf)[nOffset]);
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

size_t TcpSocket::Write(const void* buf, size_t len)
{
    if (m_bStop == true || m_bCloseReq == true || buf == nullptr || len == 0)
        return 0;

    shared_ptr<uint8_t> tmp(new uint8_t[len]);
    copy(static_cast<const uint8_t*>(buf), static_cast<const uint8_t*>(buf) + len, tmp.get());
    m_mxOutDeque.lock();
    m_atOutBytes += static_cast<uint32_t>(len);
    m_quOutData.emplace_back(tmp, static_cast<uint32_t>(len));
    m_mxOutDeque.unlock();

    m_cv.notify_all();

    return len;
}

void TcpSocket::WriteThread()
{
    m_iShutDownState &= ~2;

    mutex mut;
    unique_lock<mutex> lock(mut);

    while (m_bCloseReq == false || m_atOutBytes != 0)
    {
        m_cv.wait(lock, [&]() { return m_atOutBytes == 0 ? m_bCloseReq : true; });

        while (m_atOutBytes != 0)
        {
            fd_set writefd, errorfd;
            struct timeval timeout;

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            FD_ZERO(&writefd);
            FD_ZERO(&errorfd);

            FD_SET(m_fSock, &writefd);
            FD_SET(m_fSock, &errorfd);

            if (::select(static_cast<int>(m_fSock + 1), nullptr, &writefd, &errorfd, &timeout) == 0)
                continue;

            if (FD_ISSET(m_fSock, &errorfd))
            {
                if (m_iError == 0)
                {
                    socklen_t iLen = sizeof(m_iError);
                    getsockopt(m_fSock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&m_iError), &iLen);

                    if (m_fError && m_bStop == false)
                        m_fError(this);
                }
                break;
            }

            m_mxOutDeque.lock();
            DATA data = move(m_quOutData.front());
            m_quOutData.pop_front();
            m_atOutBytes -= BUFLEN(data);
            m_mxOutDeque.unlock();

            uint32_t transferred = ::send(m_fSock, reinterpret_cast<char*>(BUFFER(data).get()), BUFLEN(data), 0);
            if (transferred <= 0)
            {
                int iError = WSAGetLastError();
                if (iError != WSAEWOULDBLOCK)
                {
                    m_iError = iError;
                    if (m_fError && m_bStop == false)
                        m_fError(this);
                    break;
                }
                // Put the not send bytes back into the que if it is not a SSL connection. A SSL connection has the bytes still available
                shared_ptr<uint8_t> tmp(new uint8_t[BUFLEN(data)]);
                copy(BUFFER(data).get(), BUFFER(data).get() + BUFLEN(data), tmp.get());
                m_mxOutDeque.lock();
                m_quOutData.emplace_front(tmp, BUFLEN(data));
                m_mxOutDeque.unlock();
                m_atOutBytes += BUFLEN(data);
            }
            else if (transferred < BUFLEN(data)) // Less bytes send as buffer size, we put the rast back in your que
            {
                shared_ptr<uint8_t> tmp(new uint8_t[BUFLEN(data) - transferred]);
                copy(BUFFER(data).get() + transferred, BUFFER(data).get() + transferred + (BUFLEN(data) - transferred), tmp.get());
                m_mxOutDeque.lock();
                m_quOutData.emplace_front(tmp, (BUFLEN(data) - transferred));
                m_mxOutDeque.unlock();
                m_atOutBytes += (BUFLEN(data) - transferred);
            }
        }

        if (m_iError != 0)
            break;
    }

    // if we get out of the while loop, the stop request was send or we have an error
    if (m_iError == 0)
    {
        if (::shutdown(m_fSock, SD_SEND) != 0)
            m_iError = WSAGetLastError();// OutputDebugString(L"Error shutdown socket\r\n");
    }
    m_iShutDownState |= 2;

    unsigned char cExpected = 3;
    if (m_iShutDownState.compare_exchange_strong(cExpected, 7) == true)
    {
        if (m_fSock != INVALID_SOCKET)
            ::closesocket(m_fSock);
        m_fSock = INVALID_SOCKET;

        StartCloseingCB();

        if (m_pRefServSocket != nullptr || m_bSelfDelete == true)    // Auto-delete, socket created from server socket
            thread([&]() { delete this; }).detach();
    }
}

void TcpSocket::StartReceiving()
{
    m_thListen = thread(&TcpSocket::SelectThread, this);
}

void TcpSocket::Close() noexcept
{
    //OutputDebugString(L"TcpSocket::Close\r\n");
    m_bCloseReq = true; // Stops the write thread after the last byte was send
    m_cv.notify_all();
    m_bStop = true; // Stops the listening thread
}

void TcpSocket::SelfDestroy() noexcept
{
    m_bSelfDelete = true;
    Close();
}

uint32_t TcpSocket::GetBytesAvailible() const noexcept
{
    return m_atInBytes;
}

uint32_t TcpSocket::GetOutBytesInQue() const noexcept
{
    return m_atOutBytes;
}

function<void(TcpSocket*)> TcpSocket::BindFuncBytesRecived(function<void(TcpSocket*)> fBytesRecived) noexcept
{
    m_fBytesRecived.swap(fBytesRecived);
    return fBytesRecived;
}

function<void(TcpSocket*)> TcpSocket::BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted) noexcept
{
    m_fClientConneted.swap(fClientConneted);
    return fClientConneted;
}

void TcpSocket::SelectThread()
{
    m_iShutDownState &= ~1;

    bool bReadCall = false;
    mutex mxNotify;
    bool bSocketShutDown = false;

    while (m_bStop == false)
    {
        fd_set readfd, errorfd;
        struct timeval timeout;

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        FD_ZERO(&readfd);
        FD_ZERO(&errorfd);

        FD_SET(m_fSock, &readfd);
        FD_SET(m_fSock, &errorfd);

        if (::select(static_cast<int>(m_fSock + 1), &readfd, nullptr, &errorfd, &timeout) > 0)
        {
            if (FD_ISSET(m_fSock, &errorfd))
            {
                socklen_t iLen = sizeof(m_iError);
                getsockopt(m_fSock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&m_iError), &iLen);
                if (m_fError && m_bStop == false)
                    m_fError(this);
                break;
            }

            if (FD_ISSET(m_fSock, &readfd))
            {
                char buf[0x0000ffff];

                int32_t transferred = ::recv(m_fSock, buf, sizeof(buf), 0);

                if (transferred <= 0)
                {
                    if (transferred == 0)
                    {   // The connection was shutdown from the other side, there will be no more bytes to read on that connection
                        // We set the flag, so we don't read on the connection any more

                        if (::shutdown(m_fSock, SD_RECEIVE) != 0)
                            m_iError = WSAGetLastError();// OutputDebugString(L"Error shutdown socket\r\n");
                        bSocketShutDown = true;

                        while (bReadCall == true)
                            this_thread::sleep_for(chrono::milliseconds(10));

                        if (m_fBytesRecived)
                            m_fBytesRecived(this);
                        break;
                    }
                    else
                    {
                        int iError = WSAGetLastError();
                        if (iError != WSAEWOULDBLOCK)
                        {
                            m_iError = iError;
                            if (m_fError && m_bStop == false)
                                m_fError(this);
                            break;
                        }
                    }
                }
                else
                {
                    shared_ptr<uint8_t> tmp(new uint8_t[transferred]);
                    copy(buf, buf + transferred, tmp.get());
                    lock_guard<mutex> lock(m_mxInDeque);
                    m_quInData.emplace_back(tmp, transferred);
                    m_atInBytes += transferred;

                    if (m_fBytesRecived && m_bStop == false)
                    {
                        lock_guard<mutex> lock(mxNotify);
                        if (bReadCall == false)
                        {
                            bReadCall = true;
                            thread([&]()
                            {
                                mxNotify.lock();
                                while (m_atInBytes > 0)
                                {
                                    mxNotify.unlock();
                                    m_fBytesRecived(this);
                                    mxNotify.lock();
                                }
                                bReadCall = false;
                                mxNotify.unlock();
                            }).detach();
                        }
                    }
                }
            }
        }// if select
    }//while

    // if we are here, bStop is set,or m_iShutDownState has bit 1 set, or we have an error

    if (bSocketShutDown == false && m_iError == 0)
    {
        if (::shutdown(m_fSock, SD_RECEIVE) != 0)
            m_iError = WSAGetLastError();// OutputDebugString(L"Error RECEIVE shutdown socket\r\n");
    }

    while (bReadCall == true)
        this_thread::sleep_for(chrono::milliseconds(10));

    m_iShutDownState |= 1;

    unsigned char cExpected = 3;
    if (m_iShutDownState.compare_exchange_strong(cExpected, 7) == true)
    {
        if (m_fSock != INVALID_SOCKET)
            ::closesocket(m_fSock);
        m_fSock = INVALID_SOCKET;

        StartCloseingCB();

        // if it is a auto-delete class we start the auto-delete thread now
        if (m_pRefServSocket != nullptr || m_bSelfDelete == true)    // Auto-delete, socket created from server socket
            thread([&]() { delete this; }).detach();
    }
}

void TcpSocket::ConnectThread()
{
    while (m_bStop == false)
    {
        fd_set writefd, errorfd;
        struct timeval timeout;

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        FD_ZERO(&writefd);
        FD_ZERO(&errorfd);

        FD_SET(m_fSock, &writefd);
        FD_SET(m_fSock, &errorfd);

        if (::select(static_cast<int>(m_fSock + 1), nullptr, &writefd, &errorfd, &timeout) > 0)
        {
            if (FD_ISSET(m_fSock, &errorfd))
            {
                socklen_t iLen = sizeof(m_iError);
                getsockopt(m_fSock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&m_iError), &iLen);

                if (m_fError && m_bStop == false)
                    m_fError(this);
                break;
            }

            if (FD_ISSET(m_fSock, &writefd))
            {
                GetConnectionInfo();

                m_thListen = thread(&TcpSocket::SelectThread, this);
                m_thWrite = thread(&TcpSocket::WriteThread, this);

                if (m_fClientConneted)
                    m_fClientConneted(this);
                break;
            }
        }
    }

    if ((m_iError != 0 && m_fSock != INVALID_SOCKET) || m_bStop == true)
    {
        ::closesocket(m_fSock);
        m_fSock = INVALID_SOCKET;

        StartCloseingCB();

        if (m_bSelfDelete == true)    // Auto-delete, socket created from server socket
            thread([&]() { delete this; }).detach();
    }
}

bool TcpSocket::GetConnectionInfo()
{
    struct sockaddr_storage addrCl;
    socklen_t addLen = sizeof(addrCl);
    if (::getpeername(m_fSock, (struct sockaddr*)&addrCl, &addLen) != 0)  // Get the IP to where the connection was established
    {
        m_iError = WSAGetLastError();
        return false;
    }

    struct sockaddr_storage addrPe;
    addLen = sizeof(addrPe);
    if (::getsockname(m_fSock, (struct sockaddr*)&addrPe, &addLen) != 0)  // Get our IP where the connection was established
    {
        m_iError = WSAGetLastError();
        return false;
    }

    char caAddrClient[INET6_ADDRSTRLEN + 1] = { 0 };
    char servInfoClient[NI_MAXSERV] = { 0 };
    if (::getnameinfo((struct sockaddr*)&addrCl, sizeof(struct sockaddr_storage), caAddrClient, sizeof(caAddrClient), servInfoClient, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV) == 0)
    {
        m_strClientAddr = caAddrClient;
        m_sClientPort = stoi(servInfoClient);
    }
    else
    {
        m_iError = WSAGetLastError();
        return false;
    }

    char caAddrPeer[INET6_ADDRSTRLEN + 1] = { 0 };
    char servInfoPeer[NI_MAXSERV] = { 0 };
    if (::getnameinfo((struct sockaddr*)&addrPe, sizeof(struct sockaddr_storage), caAddrPeer, sizeof(caAddrPeer), servInfoPeer, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV) == 0)
    {
        m_strIFaceAddr = caAddrPeer;
        m_sIFacePort = stoi(servInfoPeer);
    }
    else
    {
        m_iError = WSAGetLastError();
        return false;
    }

    return true;
}

//************************************************************************************

TcpServer::~TcpServer()
{
    m_bStop = true; // Stops the listening thread

    if (m_thListen.joinable() == true)
        m_thListen.join();
    Delete();
}

bool TcpServer::Start(const char* const szIpAddr, const short sPort)
{
    struct addrinfo *lstAddr, hint = { 0 };
    hint.ai_family = PF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_PASSIVE;

    if (::getaddrinfo(szIpAddr, to_string(sPort).c_str(), &hint, &lstAddr) != 0)
        return false;

    bool bRet = true;

    try
    {
        for (auto curAddr = lstAddr; curAddr != nullptr; curAddr = curAddr->ai_next)
        {
            SOCKET fd = ::socket(curAddr->ai_family, curAddr->ai_socktype, curAddr->ai_protocol);
            if (fd == INVALID_SOCKET)
                throw WSAGetLastError();

            m_vSock.push_back(fd);

            SetSocketOption(fd);

            if (curAddr->ai_family == AF_INET6)
            {
                uint32_t on = 0;
                if (::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&on), sizeof(on)) == -1)
                    throw WSAGetLastError();
            }

            if (::bind(fd, curAddr->ai_addr, static_cast<int>(curAddr->ai_addrlen)) < 0)
                throw WSAGetLastError();
        }

        for (auto fSock : m_vSock)
        {
            if (::listen(fSock, SOMAXCONN) < 0)
                throw WSAGetLastError();
        }

        m_bStop = false;
        m_thListen = thread(&TcpServer::SelectThread, this);
    }

    catch (int iSocketErr)
    {
        m_iError = iSocketErr;
        Delete();
        bRet = false;
    }

    ::freeaddrinfo(lstAddr);

    return bRet;
}

unsigned short TcpServer::GetServerPort()
{
    struct sockaddr_storage addrPe;
    socklen_t addLen = sizeof(addrPe);
    if (::getsockname(m_vSock[0], (struct sockaddr*)&addrPe, &addLen) == 0)  // Get our IP where the connection was established
    {
        char caAddrPeer[INET6_ADDRSTRLEN + 1] = { 0 };
        char servInfoPeer[NI_MAXSERV] = { 0 };
        if (::getnameinfo((struct sockaddr*)&addrPe, sizeof(struct sockaddr_storage), caAddrPeer, sizeof(caAddrPeer), servInfoPeer, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV) == 0)
        {
            return stoi(servInfoPeer);
        }
    }

    return 0;
}

void TcpServer::Close() noexcept
{
    m_bStop = true; // Stops the listening thread, deletes all Sockets at the end of the listening thread
}

void TcpServer::SetSocketOption(const SOCKET& fd)
{
    BaseSocket::SetSocketOption(fd);

    SOCKOPT rc = 1;
    if (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &rc, sizeof(rc)) == -1)
        throw WSAGetLastError();
}

TcpSocket* const TcpServer::MakeClientConnection(const SOCKET& fSock)
{
    return new TcpSocket(fSock, this);
}

void TcpServer::BindNewConnection(function<void(const vector<TcpSocket*>&)> fNewConnetion) noexcept
{
    m_fNewConnection = fNewConnetion;
}

void TcpServer::Delete()
{
    while (m_vSock.size())
    {
        ::closesocket(m_vSock[0]);
        m_vSock.erase(begin(m_vSock));
    }

    lock_guard<mutex> lock(m_mtAcceptList);
    while (m_vSockAccept.size())
    {
        ::shutdown(m_vSockAccept[0], SD_BOTH);
        ::closesocket(m_vSockAccept[0]);
        m_vSockAccept.erase(begin(m_vSockAccept));
    }
}

void TcpServer::SelectThread()
{
    while (m_bStop == false)
    {
        fd_set readfd;
        struct timeval timeout;
        SOCKET maxFd = 0;

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        FD_ZERO(&readfd);

        for (auto Sock : m_vSock)
        {
            FD_SET(Sock, &readfd);
            if (Sock > maxFd)
                maxFd = Sock;
        }

        int iRes = ::select(static_cast<int>(maxFd + 1), &readfd, nullptr, nullptr, &timeout);
        if (iRes > 0)
        {
            vector<SOCKET> vSockets;

            for (auto Sock : m_vSock)
            {
                if (FD_ISSET(Sock, &readfd))
                {
                    for (int n = 0; n < 16; ++n)            // The ACCEPT_QUEUE is an optimization mechanism that allows the server to
                    {                                       // accept() up to this many connections before serving any of them.  The
                        struct sockaddr_storage addrCl;     // reason is that the timeout waiting for the accept() is much shorter
                        socklen_t addLen = sizeof(addrCl);  // than the timeout for the actual processing.

                        SOCKET fdClient = ::accept(Sock, (struct sockaddr*)&addrCl, &addLen);
                        if (fdClient == INVALID_SOCKET)
                            break;

                        if (addrCl.ss_family == AF_INET6)
                        {
                            uint32_t on = 0;
                            ::setsockopt(fdClient, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&on), sizeof(on));
                        }

                        vSockets.push_back(fdClient);
                    }
                }
            }

            if (vSockets.size() > 0)
            {
                thread([this](const vector<SOCKET> vNewSockets)
                {
                    vector<TcpSocket*> vNewConnections;
                    for (SOCKET sock : vNewSockets)
                    {
                        TcpSocket* pClient = MakeClientConnection(sock);
                        try
                        {
                            pClient->SetSocketOption(sock);
                            pClient->GetConnectionInfo();
                        }

                        catch (int iErrNo)
                        {
                            pClient->SetErrorNo(iErrNo);
                            if (m_fError)
                                m_fError(pClient);  // Must call Close() in the error callback
                            else
                                pClient->Close();
                            continue;
                        }
                        vNewConnections.push_back(pClient);
                    }
                    m_fNewConnection(vNewConnections);
                }, vSockets).detach();
            }
        }
    }

    Delete();
}

//********************************************************************************

UdpSocket::UdpSocket() : m_bCloseReq(false)
{
    atomic_init(&m_atInBytes, static_cast<uint32_t>(0));
    atomic_init(&m_atOutBytes, static_cast<uint32_t>(0));
}

UdpSocket::~UdpSocket()
{
    m_bStop = true; // Stops the listening thread
    m_bCloseReq = true;
    m_atOutBytes = 0;
    m_cv.notify_all();

    if (m_thListen.joinable() == true)
        m_thListen.join();
    if (m_thWrite.joinable() == true)
        m_thWrite.join();

    if (m_fSock != INVALID_SOCKET)
    {
        ::closesocket(m_fSock);

        if (m_fCloseing)
            m_fCloseing(this);
    }
}

bool UdpSocket::Create(const char* const szIpToWhere, const short sPort, const char* const szIpToBind/* = nullptr*/)
{
    struct addrinfo *lstAddr, hint = { 0 };
    hint.ai_family = PF_UNSPEC;
    hint.ai_socktype = SOCK_DGRAM;
    hint.ai_flags = AI_PASSIVE;

    if (::getaddrinfo(szIpToWhere, to_string(sPort).c_str(), &hint, &lstAddr) != 0)
        return false;

    bool bRet = true;

    try
    {
        m_fSock = ::socket(lstAddr->ai_family, lstAddr->ai_socktype, lstAddr->ai_protocol);
        if (m_fSock == INVALID_SOCKET)
            throw WSAGetLastError();

        SetSocketOption(m_fSock);

        if (lstAddr->ai_family == AF_INET6)
        {
            uint32_t on = 0;
            if (::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&on), sizeof(on)) == -1)
                throw WSAGetLastError();
        }

        if (szIpToBind != nullptr)
        {
            struct addrinfo *lstBind;
            if (::getaddrinfo(szIpToBind, to_string(sPort).c_str(), nullptr, &lstBind) != 0)
                throw WSAGetLastError();

            if (::bind(m_fSock, lstBind->ai_addr, static_cast<int>(lstBind->ai_addrlen)) < 0)
            {
                ::freeaddrinfo(lstBind);
                throw WSAGetLastError();
            }
            ::freeaddrinfo(lstBind);
        }
        else
        {
            if (::bind(m_fSock, lstAddr->ai_addr, static_cast<int>(lstAddr->ai_addrlen)) < 0)
                throw WSAGetLastError();
        }

        m_thListen = thread(&UdpSocket::SelectThread, this);
        m_thWrite = thread(&UdpSocket::WriteThread, this);
    }

    catch (int iSocketErr)
    {
        m_iError = iSocketErr;
        if (m_fSock != INVALID_SOCKET)
            ::closesocket(m_fSock);
        m_fSock = INVALID_SOCKET;

        bRet = false;
    }

    ::freeaddrinfo(lstAddr);

    return bRet;
}

bool UdpSocket::EnableBroadCast(bool bEnable/* = true*/)
{
    int iBroadcast = bEnable == true ? 1 : 0;
    if (::setsockopt(m_fSock, SOL_SOCKET, SO_BROADCAST, (char *)&iBroadcast, sizeof(int)) == SOCKET_ERROR)
        return false;
    return true;
}

bool UdpSocket::AddToMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex)
{
    struct addrinfo *lstAddr;
    if (::getaddrinfo(szMulticastIp, nullptr, nullptr, &lstAddr) != 0)
        return false;
    int iAddFamily = lstAddr->ai_family;
    ::freeaddrinfo(lstAddr);

    uint32_t hops = '\xff';
    uint32_t loop = 1;

    if (iAddFamily == AF_INET6)
    {
        ipv6_mreq mreq = { 0 };
        inet_pton(AF_INET6, szMulticastIp, &mreq.ipv6mr_multiaddr);
        mreq.ipv6mr_interface = nInterfaceIndex;

        // http://www.tldp.org/HOWTO/Multicast-HOWTO-6.html
        if (::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, reinterpret_cast<char*>(&mreq), sizeof(mreq)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, reinterpret_cast<char*>(&hops), sizeof(hops)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, reinterpret_cast<char*>(&loop), sizeof(loop)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_MULTICAST_IF, reinterpret_cast<char*>(&mreq.ipv6mr_interface), sizeof(mreq.ipv6mr_interface)) != 0)
        {
            m_iError = WSAGetLastError();
            return false;
        }
    }
    else
    {
        ip_mreq mreq = { 0 };
        inet_pton(AF_INET, szMulticastIp, &mreq.imr_multiaddr.s_addr);
#if defined(_WIN32) || defined(_WIN64)
        mreq.imr_interface.s_addr = htonl(nInterfaceIndex);
#else
        inet_pton(AF_INET, szInterfaceIp, &mreq.imr_interface.s_addr);
#endif

        if (::setsockopt(m_fSock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<char*>(&hops), sizeof(hops)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IP, IP_MULTICAST_LOOP, reinterpret_cast<char*>(&loop), sizeof(loop)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IP, IP_MULTICAST_IF, reinterpret_cast<char*>(&mreq.imr_interface), sizeof(mreq.imr_interface)) != 0)
        {
            m_iError = WSAGetLastError();
            return false;
        }
    }

    return true;
}

bool UdpSocket::RemoveFromMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex)
{
    struct addrinfo *lstAddr;
    if (::getaddrinfo(szMulticastIp, nullptr, nullptr, &lstAddr) != 0)
        return false;
    int iAddFamily = lstAddr->ai_family;
    ::freeaddrinfo(lstAddr);

    uint32_t AnyAddr = INADDR_ANY;

    if (iAddFamily == AF_INET6)
    {
        ipv6_mreq mreq = { 0 };
        inet_pton(AF_INET6, szMulticastIp, &mreq.ipv6mr_multiaddr);
        mreq.ipv6mr_interface = nInterfaceIndex; // use default

        if (::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_MULTICAST_IF, reinterpret_cast<char*>(&AnyAddr), sizeof(uint32_t)) != 0)
        {
            m_iError = WSAGetLastError();
            return false;
        }
    }
    else
    {
        ip_mreq mreq = { 0 };
        inet_pton(AF_INET, szMulticastIp, &mreq.imr_multiaddr.s_addr);
#if defined(_WIN32) || defined(_WIN64)
        mreq.imr_interface.s_addr = htonl(nInterfaceIndex);
#else
        inet_pton(AF_INET, szInterfaceIp, &mreq.imr_interface.s_addr);
#endif

        if (setsockopt(m_fSock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IP, IP_MULTICAST_IF, reinterpret_cast<char*>(&AnyAddr), sizeof(uint32_t)) != 0)
        {
            m_iError = WSAGetLastError();
            return false;
        }
    }

    return true;
}

uint32_t UdpSocket::Read(void* buf, uint32_t len, string& strFrom)
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
        m_quInData.emplace_front(tmp, nRest, ADDRESS(data));
        m_mxInDeque.unlock();
        m_atInBytes += nRest;
    }

    return nRet;
}

size_t UdpSocket::Write(const void* buf, size_t len, const string& strTo)
{
    if (m_bStop == true || m_bCloseReq == true || buf == nullptr || len == 0 || strTo.empty() == true)
        return 0;

    shared_ptr<uint8_t> tmp(new uint8_t[len]);
    copy(static_cast<const uint8_t*>(buf), static_cast<const uint8_t*>(buf) + len, tmp.get());
    m_mxOutDeque.lock();
    m_quOutData.emplace_back(tmp, static_cast<uint32_t>(len), strTo);
    m_atOutBytes += static_cast<uint32_t>(len);
    m_mxOutDeque.unlock();

    m_cv.notify_all();

    return len;
}

void UdpSocket::WriteThread()
{
    mutex mut;
    unique_lock<mutex> lock(mut);

    while (m_bCloseReq == false || m_atOutBytes != 0)
    {
        m_cv.wait(lock, [&]() { return m_atOutBytes == 0 ? m_bCloseReq : true; });

        while (m_atOutBytes != 0)
        {
            fd_set writefd, errorfd;
            struct timeval timeout;

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            FD_ZERO(&writefd);
            FD_ZERO(&errorfd);

            FD_SET(m_fSock, &writefd);
            FD_SET(m_fSock, &errorfd);

            if (::select(static_cast<int>(m_fSock + 1), nullptr, &writefd, &errorfd, &timeout) == 0)
                continue;

            if (FD_ISSET(m_fSock, &errorfd))
            {
                if (m_iError == 0)
                {
                    socklen_t iLen = sizeof(m_iError);
                    getsockopt(m_fSock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&m_iError), &iLen);

                    if (m_fError && m_bStop == false)
                        m_fError(this);
                }
                break;
            }

            m_mxOutDeque.lock();
            DATA data = move(m_quOutData.front());
            m_quOutData.pop_front();
            m_mxOutDeque.unlock();
            m_atOutBytes -= BUFLEN(data);

            struct addrinfo *lstAddr = nullptr;
            size_t nPosS = ADDRESS(data).find('[');
            size_t nPosE = ADDRESS(data).find(']');
            if (nPosS != string::npos && nPosE != string::npos)
            {
                if (::getaddrinfo(ADDRESS(data).substr(nPosS + 1, nPosE - 1).c_str(), ADDRESS(data).substr(nPosE + 2).c_str(), nullptr, &lstAddr) != 0)
                    break;    // we return 0, because of a wrong address
            }
            else
            {
                size_t nPos = ADDRESS(data).find(':');
                if (nPos != string::npos)
                {
                    if (::getaddrinfo(ADDRESS(data).substr(0, nPos).c_str(), ADDRESS(data).substr(nPos + 1).c_str(), nullptr, &lstAddr) != 0)
                        break;    // we return 0, because of a wrong address
                }
                else
                    break;    // we return 0, because of a wrong address
            }

            uint32_t transferred = ::sendto(m_fSock, reinterpret_cast<const char*>(BUFFER(data).get()), BUFLEN(data), 0, lstAddr->ai_addr, static_cast<int>(lstAddr->ai_addrlen));
            ::freeaddrinfo(lstAddr);
            if (transferred <= 0)
            {
                m_iError = WSAGetLastError();
                if (m_iError != WSAEWOULDBLOCK)
                {
                    if (m_fError && m_bStop == false)
                        m_fError(this);
                    break;
                }
                // Put the not send bytes back into the que if it is not a SSL connection. A SSL connection has the bytes still available
                shared_ptr<uint8_t> tmp(new uint8_t[BUFLEN(data)]);
                copy(BUFFER(data).get(), BUFFER(data).get() + BUFLEN(data), tmp.get());
                m_mxOutDeque.lock();
                m_quOutData.emplace_front(tmp, BUFLEN(data), ADDRESS(data));
                m_mxOutDeque.unlock();
                m_atOutBytes += BUFLEN(data);
            }
            else if (transferred < BUFLEN(data)) // Less bytes send as buffer size, we put the rast back in your que
            {
                shared_ptr<uint8_t> tmp(new uint8_t[BUFLEN(data) - transferred]);
                copy(BUFFER(data).get() + transferred, BUFFER(data).get() + transferred + (BUFLEN(data) - transferred), tmp.get());
                m_mxOutDeque.lock();
                m_quOutData.emplace_front(tmp, (BUFLEN(data) - transferred), ADDRESS(data));
                m_mxOutDeque.unlock();
                m_atOutBytes += (BUFLEN(data) - transferred);
            }


        }
    }

    // if we get out of the while loop, the stop request was send or we have an error
    if (m_iError == 0)
    {
        if (::shutdown(m_fSock, SD_SEND) != 0)
            m_iError = WSAGetLastError();// OutputDebugString(L"Error shutdown socket\r\n");
    }
    m_iShutDownState |= 2;
}

void UdpSocket::Close() noexcept
{
    m_bCloseReq = true; // Stops the write thread after the last byte was send
    m_cv.notify_all();
    m_bStop = true; // Stops the listening thread
}

uint32_t UdpSocket::GetBytesAvailible() const noexcept
{
    return m_atInBytes;
}

uint32_t UdpSocket::GetOutBytesInQue() const noexcept
{
    return m_atOutBytes;
}

function<void(UdpSocket*)> UdpSocket::BindFuncBytesRecived(function<void(UdpSocket*)> fBytesRecived) noexcept
{
    m_fBytesRecived.swap(fBytesRecived);
    return fBytesRecived;
}

void UdpSocket::SelectThread()
{
    bool bReadCall = false;
    mutex mxNotify;
    bool bSocketShutDown = false;

    while (m_bStop == false)
    {
        fd_set readfd, errorfd;
        struct timeval timeout;

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        FD_ZERO(&readfd);
        FD_ZERO(&errorfd);

        FD_SET(m_fSock, &readfd);
        FD_SET(m_fSock, &errorfd);

        if (::select(static_cast<int>(m_fSock + 1), &readfd, nullptr, &errorfd, &timeout) > 0)
        {
            if (FD_ISSET(m_fSock, &errorfd))
            {
                socklen_t iLen = sizeof(m_iError);
                getsockopt(m_fSock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&m_iError), &iLen);
                if (m_fError && m_bStop == false)
                    m_fError(this);
                break;
            }

            if (FD_ISSET(m_fSock, &readfd))
            {
                char buf[0x0000ffff];

                union
                {
                    sockaddr_in sin;
                    sockaddr_in6 sin6;
                }SenderAddr;
                socklen_t sinLen = sizeof(SenderAddr);

                int32_t transferred = ::recvfrom(m_fSock, buf, sizeof(buf), 0, (sockaddr*)&SenderAddr, &sinLen);

                if (transferred <= 0)
                {
                    if (transferred == 0)
                    {   // The connection was shutdown from the other side, there will be no more bytes to read on that connection
                        // We set the flag, so we don't read on the connection any more
                        if (::shutdown(m_fSock, SD_RECEIVE) != 0)
                            m_iError = WSAGetLastError();// OutputDebugString(L"Error shutdown socket\r\n");
                        bSocketShutDown = true;

                        if (m_fBytesRecived)
                        {
                            while (bReadCall == true)
                                this_thread::sleep_for(chrono::milliseconds(10));
                            m_fBytesRecived(this);
                        }
                        break;
                    }
                    else
                    {
                        m_iError = WSAGetLastError();
                        if (m_iError != WSAEWOULDBLOCK)
                        {
                            if (m_fError && m_bStop == false)
                                m_fError(this);
                            break;
                        }
                    }
                }
                else
                {
                    stringstream strAbsender;
                    char caAddrBuf[INET6_ADDRSTRLEN + 1] = { 0 };
                    if (SenderAddr.sin6.sin6_family == AF_INET6)
                    {
                        strAbsender << "[" << inet_ntop(SenderAddr.sin6.sin6_family, &SenderAddr.sin6.sin6_addr, caAddrBuf, sizeof(caAddrBuf));
                        strAbsender << "]:" << ntohs(SenderAddr.sin6.sin6_port);
                    }
                    else
                    {
                        strAbsender << inet_ntop(SenderAddr.sin.sin_family, &SenderAddr.sin.sin_addr, caAddrBuf, sizeof(caAddrBuf));
                        strAbsender << ":" << ntohs(SenderAddr.sin.sin_port);
                    }

                    shared_ptr<uint8_t> tmp(new uint8_t[transferred]);
                    copy(buf, buf + transferred, tmp.get());
                    m_mxInDeque.lock();
                    m_quInData.emplace_back(tmp, transferred, strAbsender.str());
                    m_atInBytes += transferred;
                    m_mxInDeque.unlock();

                    if (m_fBytesRecived && m_bStop == false)
                    {
                        lock_guard<mutex> lock(mxNotify);
                        if (bReadCall == false)
                        {
                            bReadCall = true;
                            thread([&]()
                            {
                                mxNotify.lock();
                                while (m_atInBytes > 0)
                                {
                                    mxNotify.unlock();
                                    m_fBytesRecived(this);
                                    mxNotify.lock();
                                }
                                bReadCall = false;
                                mxNotify.unlock();
                            }).detach();
                        }
                    }
                }
            }
        }
    }

    if (bSocketShutDown == false && m_iError == 0)
    {
        if (::shutdown(m_fSock, SD_RECEIVE) != 0)
            m_iError = WSAGetLastError();// OutputDebugString(L"Error RECEIVE shutdown socket\r\n");
    }

    while (bReadCall == true)
        this_thread::sleep_for(chrono::milliseconds(10));

    m_iShutDownState |= 1;
}
