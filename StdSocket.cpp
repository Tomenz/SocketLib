/* Copyright (C) 2016-2020 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
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
InitSocket& SocketInit = InitSocket::GetInstance();

InitSocket& InitSocket::GetInstance() noexcept
{
    static InitSocket iniSocket;
    return iniSocket;
}

InitSocket::~InitSocket()
{
#if defined(_WIN32) || defined(_WIN64)
    if (m_hIFaceNotify != nullptr)
        CancelMibChangeNotify2(m_hIFaceNotify);
    ::WSACleanup();
#else
    m_bStopThread = true;
    if (m_thIpChange.joinable() == true)
        m_thIpChange.join();
#endif
}

void InitSocket::SetAddrNotifyCallback(const function<void(bool, const string&, int, int)>& fnCbAddrNotify)
{
    m_fnCbAddrNotify = fnCbAddrNotify;
    if (m_fnCbAddrNotify)
    {   // notify on current ip addresses
        for (auto iter : m_vCurIPAddr)
            m_fnCbAddrNotify(true, get<0>(iter), get<1>(iter), get<2>(iter));
    }

#if defined(_WIN32) || defined(_WIN64)
    if (m_hIFaceNotify == nullptr)
        NotifyIpInterfaceChange(AF_UNSPEC, IpIfaceChanged, this, TRUE, &m_hIFaceNotify);
#else
    if (m_thIpChange.joinable() == false)
        m_thIpChange = thread(&InitSocket::IpChangeThread, this);
#endif
}

InitSocket::InitSocket() noexcept
{
#if defined(_WIN32) || defined(_WIN64)
    WSADATA wsaData;
    ::WSAStartup(MAKEWORD(2, 2), &wsaData);
    m_hIFaceNotify = nullptr;
#else
    //signal(SIGPIPE, SIG_IGN);
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGPIPE);
    sigprocmask(SIG_BLOCK, &sigset, NULL);
    BaseSocketImpl::EnumIpAddresses(bind(&InitSocket::CbEnumIpAdressen, this, placeholders::_1, placeholders::_2, placeholders::_3, placeholders::_4), &m_vCurIPAddr);
    m_bStopThread = false;
#endif
}

#if defined (_WIN32) || defined (_WIN64)
VOID __stdcall InitSocket::IpIfaceChanged(PVOID CallerContext, PMIB_IPINTERFACE_ROW /*pRow*/, MIB_NOTIFICATION_TYPE NotificationType)
{
    InitSocket* const pThis = static_cast<InitSocket*>(CallerContext);
    if (pThis == nullptr)
        return;

    function<int(int, const string&, int, void*)> fnCb = bind(&InitSocket::CbEnumIpAdressen, pThis, placeholders::_1, placeholders::_2, placeholders::_3, placeholders::_4);
    vector<tuple<string, int, int>> vNewIPAddr;
    BaseSocketImpl::EnumIpAddresses(fnCb, &vNewIPAddr);
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

    struct sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    if (bind(fSock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == -1)
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
                string buf(4096, 0);
                int32_t transferred = ::recv(fSock, &buf[0], buf.size(), 0);

                if (transferred > 0)
                {
                    struct nlmsghdr* nlh = reinterpret_cast<struct nlmsghdr*>(&buf[0]);
                    while ((NLMSG_OK(nlh, static_cast<unsigned int>(transferred))) && (nlh->nlmsg_type != NLMSG_DONE))
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
                            BaseSocketImpl::EnumIpAddresses(bind(&InitSocket::CbEnumIpAdressen, this, placeholders::_1, placeholders::_2, placeholders::_3, placeholders::_4), &vNewIPAddr);
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

int InitSocket::CbEnumIpAdressen(int iFamily, const string& strIp, int nInterFaceId, void* vpUserParam)
{
    if (vpUserParam == nullptr)
        return 1;   // Stop enumeration, doesn't make sense

    vector<tuple<const string, int, int>>* pmaStrIps = static_cast<vector<tuple<const string, int, int>>*>(vpUserParam);
    pmaStrIps->push_back(make_tuple(strIp, iFamily, nInterFaceId));

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

function<void(const uint16_t, const char*, size_t, bool)> BaseSocketImpl::s_fTrafficDebug;
deque<unique_ptr<BaseSocket>> BaseSocketImpl::s_lstClientSocket;
mutex BaseSocketImpl::s_mxClientSocket;

BaseSocketImpl::BaseSocketImpl() noexcept : m_fSock(INVALID_SOCKET), m_bStop(false), m_iError(0), m_iErrLoc(0), m_iShutDownState(0), m_fError(bind(&BaseSocketImpl::OnError, this)), m_pvUserData(nullptr), m_pBkRef(nullptr)
{
}

BaseSocketImpl::BaseSocketImpl(BaseSocketImpl* pBaseSocket) : m_fSock(INVALID_SOCKET), m_bStop(pBaseSocket->m_bStop), m_iError(pBaseSocket->m_iError), m_iErrLoc(pBaseSocket->m_iErrLoc), m_iShutDownState(0), m_fError(bind(&BaseSocketImpl::OnError, this)), m_pvUserData(pBaseSocket->m_pvUserData), m_pBkRef(nullptr)
{
    lock_guard<mutex> lock(pBaseSocket->m_mxWrite);
    swap(m_fSock, pBaseSocket->m_fSock);
    swap(m_fError, pBaseSocket->m_fError);
    swap(m_fErrorParam, pBaseSocket->m_fErrorParam);
    swap(m_fClosing, pBaseSocket->m_fClosing);
    swap(m_fClosingParam, pBaseSocket->m_fClosingParam);
    m_iShutDownState.exchange(pBaseSocket->m_iShutDownState);
}

BaseSocketImpl::~BaseSocketImpl()
{
    if (m_thListen.joinable() == true)
        m_thListen.join();
    if (m_thWrite.joinable() == true)
        m_thWrite.join();
    if (m_thClose.joinable() == true)
        m_thClose.join();
}

function<void(BaseSocket*)> BaseSocketImpl::BindErrorFunction(function<void(BaseSocket*)> fError) noexcept
{
    m_fError.swap(fError);
    return fError;
}

function<void(BaseSocket*, void*)> BaseSocketImpl::BindErrorFunction(function<void(BaseSocket*, void*)> fError) noexcept
{
    m_fErrorParam.swap(fError);
    return fError;
}

function<void(BaseSocket*)> BaseSocketImpl::BindCloseFunction(function<void(BaseSocket*)> fClosing) noexcept
{
    m_fClosing.swap(fClosing);
    return fClosing;
}

function<void(BaseSocket*, void*)> BaseSocketImpl::BindCloseFunction(function<void(BaseSocket*, void*)> fClosing) noexcept
{
    m_fClosingParam.swap(fClosing);
    return fClosing;
}

void BaseSocketImpl::SetCallbackUserData(void* pUserData) noexcept
{
    m_pvUserData = pUserData;
}

void BaseSocketImpl::SetSocketOption(const SOCKET& fd)
{
    constexpr SOCKOPT rc = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof(rc)) != 0)
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

void BaseSocketImpl::OnError()
{
    Close();
}

void BaseSocketImpl::StartClosingCB()
{
    m_mxFnClosing.lock();
    if (m_fClosingParam)
    {
        function<void(BaseSocket*, void*)> tmpfun;
        m_fClosingParam.swap(tmpfun);
        m_mxFnClosing.unlock();
        tmpfun(m_pBkRef, m_pvUserData);
    }
    else if (m_fClosing)
    {
        function<void(BaseSocket*)> tmpfun;
        m_fClosing.swap(tmpfun);
        m_mxFnClosing.unlock();
        tmpfun(m_pBkRef);
    }
    else
        m_mxFnClosing.unlock();
}

uint16_t BaseSocketImpl::GetSocketPort()
{
    struct sockaddr_storage addrPe;
    socklen_t addLen = sizeof(addrPe);
    if (::getsockname(m_fSock, reinterpret_cast<struct sockaddr*>(&addrPe), &addLen) == 0)  // Get our IP where the connection was established
    {
        string caAddrPeer(INET6_ADDRSTRLEN + 1, 0);
        string servInfoPeer(NI_MAXSERV, 0);
        if (::getnameinfo(reinterpret_cast<struct sockaddr*>(&addrPe), sizeof(struct sockaddr_storage), &caAddrPeer[0], INET6_ADDRSTRLEN, &servInfoPeer[0], NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV) == 0)
        {
            return static_cast<uint16_t>(stoi(&servInfoPeer[0]));
        }
    }

    return 0;
}

int BaseSocketImpl::EnumIpAddresses(function<int(int, const string&, int, void*)> fnCallBack, void* vpUser)
{
#if defined(_WIN32) || defined(_WIN64)
    ULONG outBufLen = sizeof(IP_ADAPTER_ADDRESSES_LH) * 255;
    auto pAddressList = make_unique<IP_ADAPTER_ADDRESSES_LH[]>(255);
    if (pAddressList == nullptr)
        return ERROR_OUTOFMEMORY;
    DWORD ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, &pAddressList[0], &outBufLen);

    if (ret == ERROR_BUFFER_OVERFLOW)
    {
        pAddressList = make_unique<IP_ADAPTER_ADDRESSES_LH[]>(outBufLen / sizeof(IP_ADAPTER_ADDRESSES_LH) + 1);
        if (pAddressList == nullptr)
            return ERROR_OUTOFMEMORY;
        ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, &pAddressList[0], &outBufLen);
    }

    if (ret == ERROR_SUCCESS)
    {
        for (PIP_ADAPTER_ADDRESSES pCurrentAddresses = &pAddressList[0]; pCurrentAddresses != nullptr; pCurrentAddresses = pCurrentAddresses->Next)
        {
            if (pCurrentAddresses->IfType == IF_TYPE_SOFTWARE_LOOPBACK || pCurrentAddresses->OperStatus != IfOperStatusUp)
                continue;

            for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrentAddresses->FirstUnicastAddress; pUnicast != nullptr; pUnicast = pUnicast->Next)
            {
                if ((pUnicast->Flags & IP_ADAPTER_ADDRESS_TRANSIENT) == IP_ADAPTER_ADDRESS_TRANSIENT)
                    continue;

                string strTmp(255, 0);
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6)
                    strTmp = inet_ntop(AF_INET6, &reinterpret_cast<struct sockaddr_in6*>(pUnicast->Address.lpSockaddr)->sin6_addr, &strTmp[0], strTmp.size());
                else
                    strTmp = inet_ntop(AF_INET, &reinterpret_cast<struct sockaddr_in*>(pUnicast->Address.lpSockaddr)->sin_addr, &strTmp[0], strTmp.size());
                if (fnCallBack(pUnicast->Address.lpSockaddr->sa_family, strTmp, pCurrentAddresses->IfIndex, vpUser) != 0)
                {
                    return ERROR_CANCELLED;
                }
            }
        }
    }

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

void BaseSocketImpl::SetAddrNotifyCallback(const function<void(bool, const string&, int, int)>& fnCbAddrNotify)
{
    InitSocket::GetInstance().SetAddrNotifyCallback(fnCbAddrNotify);
}

//************************************************************************************

TcpSocketImpl::TcpSocketImpl(BaseSocket* pBkRef) : m_pRefServSocket(nullptr), m_bCloseReq(false), m_sClientPort(0), m_sIFacePort(0), m_bSelfDelete(false)
{
    atomic_init(&m_atInBytes, static_cast<size_t>(0));
    atomic_init(&m_atOutBytes, static_cast<size_t>(0));
    m_pBkRef = pBkRef;
}

TcpSocketImpl::TcpSocketImpl(BaseSocket* pBkRef, TcpSocketImpl* pTcpSocketImpl) : BaseSocketImpl(pTcpSocketImpl), m_pRefServSocket(pTcpSocketImpl->m_pRefServSocket), m_bCloseReq(pTcpSocketImpl->m_bCloseReq), m_bSelfDelete(pTcpSocketImpl->m_bSelfDelete)
{
    pTcpSocketImpl->m_pRefServSocket = nullptr;

    atomic_init(&m_atInBytes, static_cast<size_t>(0));
    atomic_init(&m_atOutBytes, static_cast<size_t>(0));

    pTcpSocketImpl->m_mxInDeque.lock();
    swap(m_quInData, pTcpSocketImpl->m_quInData);
    m_atInBytes.exchange(pTcpSocketImpl->m_atInBytes);
    swap(m_fBytesReceived, pTcpSocketImpl->m_fBytesReceived);
    swap(m_fBytesReceivedParam, pTcpSocketImpl->m_fBytesReceivedParam);
    pTcpSocketImpl->m_mxInDeque.unlock();

    pTcpSocketImpl->m_mxOutDeque.lock();
    swap(m_quOutData, pTcpSocketImpl->m_quOutData);
    m_atOutBytes.exchange(pTcpSocketImpl->m_atOutBytes);
    pTcpSocketImpl->m_mxOutDeque.unlock();

    swap(m_strClientAddr, pTcpSocketImpl->m_strClientAddr);
    swap(m_sClientPort, pTcpSocketImpl->m_sClientPort);
    swap(m_strIFaceAddr, pTcpSocketImpl->m_strIFaceAddr);
    swap(m_sIFacePort, pTcpSocketImpl->m_sIFacePort);

    swap(m_fClientConnected, pTcpSocketImpl->m_fClientConnected);
    swap(m_fClientConnectedParam, pTcpSocketImpl->m_fClientConnectedParam);
    swap(m_fClientConnectedSsl, pTcpSocketImpl->m_fClientConnectedSsl);

    m_iShutDownState = 7;
    m_thWrite = thread(&TcpSocketImpl::WriteThread, this);
	m_pBkRef = pBkRef;
}

TcpSocketImpl::~TcpSocketImpl()
{
    //OutputDebugString(L"TcpSocketImpl::~TcpSocketImpl\r\n");
    m_bStop = true; // Stops the listening thread
    const bool bIsLocked = m_mxWrite.try_lock();
    m_bCloseReq = true;
    m_atOutBytes = 0;
    m_cv.notify_all();
    if (bIsLocked == true)
        m_mxWrite.unlock();

    if (m_thConnect.joinable() == true)
        m_thConnect.join();

    if (m_fSock != INVALID_SOCKET)
    {
        ::closesocket(m_fSock);
        m_fSock = INVALID_SOCKET;

        StartClosingCB();
    }
}

bool TcpSocketImpl::Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint/* = AF_UNSPEC*/)
{
    if (m_fSock != INVALID_SOCKET)
    {
        ::closesocket(m_fSock);
        m_fSock = INVALID_SOCKET;
    }

    struct addrinfo* lstAddr{}, hint{};
    hint.ai_family = AddrHint;
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
            constexpr uint32_t on = 0;
            if (::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&on), sizeof(on)) == -1)
                throw WSAGetLastError();
        }

        const int rc = ::connect(m_fSock, lstAddr->ai_addr, static_cast<int>(lstAddr->ai_addrlen));
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
            m_thConnect = thread(&TcpSocketImpl::ConnectThread, this);
        }
        else
        {
            GetConnectionInfo();

            m_thListen = thread(&TcpSocketImpl::SelectThread, this);
            m_thWrite = thread(&TcpSocketImpl::WriteThread, this);

            TcpSocket* pTcpSocket = dynamic_cast<TcpSocket*>(m_pBkRef);
            if (m_fClientConnectedParam && pTcpSocket != nullptr)
                m_fClientConnectedParam(pTcpSocket, m_pvUserData);
            else if (m_fClientConnected && pTcpSocket != nullptr)
                m_fClientConnected(pTcpSocket);

            if (m_fClientConnectedSsl)
                m_fClientConnectedSsl(nullptr);
        }
    }

    catch (const int iSocketErr)
    {
        m_iError = iSocketErr;
        m_iErrLoc = 1;

        if (m_fSock != INVALID_SOCKET)
        {
            ::closesocket(m_fSock);
            m_fSock = INVALID_SOCKET;
        }
        bRet = false;
    }

    ::freeaddrinfo(lstAddr);

    return bRet;
}

void TcpSocketImpl::SetSocketOption(const SOCKET& fd)
{
    BaseSocketImpl::SetSocketOption(fd);

    constexpr SOCKOPT rc = 1;
    if (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &rc, sizeof(rc)) == -1)
        throw WSAGetLastError();

    uint32_t nSize = 0x100000;
    constexpr int iLen = sizeof(nSize);
    if (::setsockopt(m_fSock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<char*>(&nSize), iLen) == -1)
        throw WSAGetLastError();
    nSize = 0x100000;
    if (::setsockopt(m_fSock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char*>(&nSize), iLen) == -1)
        throw WSAGetLastError();
}

size_t TcpSocketImpl::Read(void* buf, size_t len)
{
    if (m_atInBytes == 0 || buf == nullptr || len == 0)
        return 0;

    size_t nOffset = 0;
    size_t nRet = 0;

    NextFromQue:
    m_mxInDeque.lock();
    DATA data = move(m_quInData.front());
    m_quInData.pop_front();
    m_mxInDeque.unlock();

    // Copy the data into the destination buffer
    const size_t nToCopy = min(BUFLEN(data), len);
    copy_n(&BUFFER(data)[0], nToCopy, &static_cast<uint8_t*>(buf)[nOffset]);
    m_atInBytes -= nToCopy;
    nRet += nToCopy;

    if (nToCopy < BUFLEN(data))
    {   // Put the Rest of the Data back to the Que
        size_t nRest = BUFLEN(data) - nToCopy;
        auto tmp = make_unique<uint8_t[]>(nRest);
        copy_n(&BUFFER(data)[nToCopy], nToCopy + nRest, &tmp[0]);
        m_mxInDeque.lock();
        m_quInData.emplace_front(move(tmp), nRest);
        m_mxInDeque.unlock();
    }
    else if (m_quInData.size() > 0 && len > nToCopy)
    {
        len -= nToCopy;
        nOffset += nToCopy;
        goto NextFromQue;
    }

    return nRet;
}

size_t TcpSocketImpl::PutBackRead(void* buf, size_t len)
{
    if (buf == nullptr || len == 0)
        return 0;

    auto tmp = make_unique<uint8_t[]>(len);
    copy_n(&static_cast<const uint8_t*>(buf)[0], len, &tmp[0]);
    m_mxInDeque.lock();
    m_quInData.emplace_front(move(tmp), len);
    m_atInBytes += len;
    m_mxInDeque.unlock();

    return len;
}

void TcpSocketImpl::TriggerWriteThread()
{
    unique_lock<mutex> lock(m_mxWrite);
    m_cv.notify_all();
}

size_t TcpSocketImpl::Write(const void* buf, size_t len)
{
    if (m_bStop == true || m_bCloseReq == true || buf == nullptr || len == 0)
        return 0;

    if (s_fTrafficDebug != nullptr)
        s_fTrafficDebug(static_cast<uint16_t>(m_fSock), static_cast<const char*>(buf), len, true);

    if (m_fnSslInitDone != nullptr && m_fnSslInitDone() != 1)
    {
        auto tmp = make_unique<uint8_t[]>(len);
        copy_n(&static_cast<const uint8_t*>(buf)[0], len, &tmp[0]);
        lock_guard<mutex> lock(m_mxOutDeque);
        m_quTmpOutData.emplace_back(move(tmp), len);
        return len;
    }

    int iRet = 0;
    if (m_fnSslEncode == nullptr || (iRet = m_fnSslEncode(reinterpret_cast<const uint8_t*>(buf), len), iRet == 0))
    {
        auto tmp = make_unique<uint8_t[]>(len);
        copy_n(&static_cast<const uint8_t*>(buf)[0], len, &tmp[0]);
        m_mxOutDeque.lock();
        m_atOutBytes += len;
        m_quOutData.emplace_back(move(tmp), len);
        m_mxOutDeque.unlock();

        iRet = 1;   // Trigger WriteThread
    }

    if (iRet > 0)
        TriggerWriteThread();

    return len;
}

void TcpSocketImpl::WriteThread()
{
    m_iShutDownState &= static_cast<uint8_t>(~2);

    unique_lock<mutex> lock(m_mxWrite);

    while (m_bCloseReq == false || m_atOutBytes != 0)
    {
        if (m_bCloseReq == false && m_atOutBytes == 0)
            m_cv.wait(lock, [&]() noexcept { return m_atOutBytes == 0 ? m_bCloseReq : true; });

        if (m_fSock == INVALID_SOCKET)
            break;

        if (m_atOutBytes != 0)
        {
            fd_set writefd{}, errorfd{};
            struct timeval timeout{};

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            FD_ZERO(&writefd);
            FD_ZERO(&errorfd);

            FD_SET(m_fSock, &writefd);
            FD_SET(m_fSock, &errorfd);

            if (::select(static_cast<int>(m_fSock + 1), nullptr, &writefd, &errorfd, &timeout) == 0)
            {
                if (m_bCloseReq == false) continue;
                break;
            }

            if (FD_ISSET(m_fSock, &errorfd))
            {
                if (m_iError == 0)
                {
                    socklen_t iLen = sizeof(m_iError);
                    getsockopt(m_fSock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&m_iError), &iLen);
                    m_iErrLoc = 2;
                    lock.unlock();
                    thread thErrorCb([&]()
                    {
                        if (m_fErrorParam && m_bStop == false)
                            m_fErrorParam(m_pBkRef, m_pvUserData);
                        else if (m_fError && m_bStop == false)
                            m_fError(m_pBkRef);
                    });
                    thErrorCb.join();
                    lock.lock();
                }
                break;
            }

            m_mxOutDeque.lock();
            if (m_quOutData.size() == 0)
            {
                m_atOutBytes = 0;
                m_mxOutDeque.unlock();
                continue;
            }
            DATA data = move(m_quOutData.front());
            m_quOutData.pop_front();
            m_atOutBytes -= BUFLEN(data);
            m_mxOutDeque.unlock();

            const uint32_t transferred = ::send(m_fSock, reinterpret_cast<char*>(&BUFFER(data)[0]), static_cast<int>(BUFLEN(data)), 0);
            if (static_cast<int32_t>(transferred) <= 0)
            {
                const int iError = WSAGetLastError();
                if (iError != WSAEWOULDBLOCK)
                {
                    m_iError = iError;
                    m_iErrLoc = 3;
                    lock.unlock();
                    thread thErrorCb([&]()
                    {
                        if (m_fErrorParam && m_bStop == false)
                            m_fErrorParam(m_pBkRef, m_pvUserData);
                        else if (m_fError && m_bStop == false)
                            m_fError(m_pBkRef);
                    });
                    thErrorCb.join();
                    lock.lock();
                    break;
                }
                // Put the not send bytes back into the que if it is not a SSL connection. A SSL connection has the bytes still available
                auto tmp = make_unique<uint8_t[]>(BUFLEN(data));
                copy_n(&BUFFER(data)[0], BUFLEN(data), &tmp[0]);
                m_mxOutDeque.lock();
                m_atOutBytes += BUFLEN(data);
                m_quOutData.emplace_front(move(tmp), BUFLEN(data));
                m_mxOutDeque.unlock();
            }
            else if (transferred < BUFLEN(data)) // Less bytes send as buffer size, we put the rast back in your que
            {
                auto tmp = make_unique<uint8_t[]>(BUFLEN(data) - transferred);
                copy_n(&BUFFER(data)[transferred], BUFLEN(data) - transferred, &tmp[0]);
                m_mxOutDeque.lock();
                m_atOutBytes += (BUFLEN(data) - transferred);
                m_quOutData.emplace_front(move(tmp), (BUFLEN(data) - transferred));
                m_mxOutDeque.unlock();
            }
        }

        if (m_iError != 0)
            break;
    }

    lock.unlock();

    // if we get out of the while loop, the stop request was send or we have an error
    if (m_iError == 0 && m_fSock != INVALID_SOCKET)
    {
        if (::shutdown(m_fSock, SD_SEND) != 0)
        {
            m_iError = WSAGetLastError();// OutputDebugString(L"Error shutdown socket\r\n");
            m_iErrLoc = 4;
        }
    }
    m_iShutDownState |= 2;

    unsigned char cExpected = 7;
    if (m_iShutDownState.compare_exchange_strong(cExpected, 15) == true)
    {
        if (m_fSock != INVALID_SOCKET)
        {
            ::closesocket(m_fSock);
            m_fSock = INVALID_SOCKET;
        }
        StartClosingCB();

        if (m_pRefServSocket != nullptr || m_bSelfDelete == true)    // Auto-delete, socket created from server socket
            Delete();// thread([&]() { delete this; }).detach();
    }
}

void TcpSocketImpl::StartReceiving()
{
    m_thListen = thread(&TcpSocketImpl::SelectThread, this);
}

void TcpSocketImpl::Close()
{
    //OutputDebugString(L"TcpSocketImpl::Close\r\n");
    m_bCloseReq = true; // Stops the write thread after the last byte was send
    do
    {
        const bool bIsLocked = m_mxWrite.try_lock();
        m_cv.notify_all();
        if (bIsLocked == true)
            m_mxWrite.unlock();
    } while ((m_iShutDownState & 2) == 0 && m_iError == 0); // Wait until the write thread is finished
    m_bStop = true; // Stops the listening thread

    if (m_pRefServSocket == nullptr && m_iShutDownState == 15 && (m_fClosing || m_fClosingParam) && m_thClose.joinable() == false)
    {
        m_thClose = thread([&]() {
            StartClosingCB();
        });

        while (m_fClosingParam != nullptr || m_fClosing != nullptr)
            this_thread::sleep_for(chrono::milliseconds(1));
    }
}

void TcpSocketImpl::SelfDestroy()
{
    m_bSelfDelete = true;
    m_pBkRef = nullptr;
    Close();
}

void TcpSocketImpl::Delete()
{
    thread([&]()
        {
            if (m_pBkRef == nullptr)
            {
                delete this;
                return;
            }
            TcpSocket* pSock = dynamic_cast<TcpSocket*>(m_pBkRef);
            lock_guard<mutex> lock(s_mxClientSocket);

            auto it = find_if(begin(s_lstClientSocket), end(s_lstClientSocket), [&](auto& item) noexcept { return item.get() == pSock; });
            if (it != end(s_lstClientSocket))
                s_lstClientSocket.erase(it);
            else
                delete pSock;
        }).detach();
}

size_t TcpSocketImpl::GetBytesAvailable() const noexcept
{
    return m_atInBytes;
}

size_t TcpSocketImpl::GetOutBytesInQue() const noexcept
{
    return m_atOutBytes;
}

function<void(TcpSocket*)> TcpSocketImpl::BindFuncBytesReceived(function<void(TcpSocket*)> fBytesReceived) noexcept
{
    m_fBytesReceived.swap(fBytesReceived);
    return fBytesReceived;
}

function<void(TcpSocket*, void*)> TcpSocketImpl::BindFuncBytesReceived(function<void(TcpSocket*, void*)> fBytesReceived) noexcept
{
    m_fBytesReceivedParam.swap(fBytesReceived);
    return fBytesReceived;
}

function<void(TcpSocket*)> TcpSocketImpl::BindFuncConEstablished(function<void(TcpSocket*)> fClientConnected) noexcept
{
    m_fClientConnected.swap(fClientConnected);
    return fClientConnected;
}
function<void(TcpSocket*, void*)> TcpSocketImpl::BindFuncConEstablished(function<void(TcpSocket*, void*)> fClientConnected) noexcept
{
    m_fClientConnectedParam.swap(fClientConnected);
    return fClientConnected;
}
void TcpSocketImpl::BindFuncConEstablished(function<void(TcpSocketImpl*)> fClientConnected) noexcept
{
    m_fClientConnectedSsl.swap(fClientConnected);
}

void TcpSocketImpl::SelectThread()
{
    m_iShutDownState &= static_cast<uint8_t>(~1);

    bool bReadCall = false;
    mutex mxNotify;
    bool bSocketShutDown = false;
	auto buf = make_unique<char[]>(0x0000ffff);

    while (m_bStop == false)
    {
        if (m_atInBytes > 0x80000)  // More than 512 KB in the receive buffer
        {
            this_thread::sleep_for(chrono::milliseconds(1));
            continue;
        }

        fd_set readfd{}, errorfd{};
        struct timeval timeout{};

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
                m_iErrLoc = 5;
                if (m_fErrorParam && m_bStop == false)
                    m_fErrorParam(m_pBkRef, m_pvUserData);
                else if (m_fError && m_bStop == false)
                    m_fError(m_pBkRef);
                break;
            }

            if (FD_ISSET(m_fSock, &readfd))
            {
                do
                {
                    int32_t transferred = ::recv(m_fSock, &buf[0], 0x0000ffff, 0);

                    if (transferred <= 0)
                    {
                        if (transferred == 0)
                        {   // The connection was shutdown from the other side, there will be no more bytes to read on that connection
                            // We set the flag, so we don't read on the connection any more

                            if (::shutdown(m_fSock, SD_RECEIVE) != 0)
                            {
                                m_iError = WSAGetLastError();// OutputDebugString(L"Error shutdown socket\r\n");
                                m_iErrLoc = 6;
                            }
                            bSocketShutDown = true;

                            while (bReadCall == true)
                                this_thread::sleep_for(chrono::milliseconds(10));

                            TcpSocket* pTcpSocket = dynamic_cast<TcpSocket*>(m_pBkRef);
                            if (m_fBytesReceivedParam && pTcpSocket != nullptr)
                                m_fBytesReceivedParam(pTcpSocket, m_pvUserData);
                            else if (m_fBytesReceived && pTcpSocket != nullptr)
                                m_fBytesReceived(pTcpSocket);
                        }
                        else
                        {
                            const int iError = WSAGetLastError();
                            if (iError != WSAEWOULDBLOCK)
                            {
                                m_iError = iError;
                                m_iErrLoc = 7;
                                if (m_fErrorParam && m_bStop == false)
                                    m_fErrorParam(m_pBkRef, m_pvUserData);
                                else if (m_fError && m_bStop == false)
                                    m_fError(m_pBkRef);
                            }
                        }
                        break;
                    }
                    else
                    {
                        bool bZeroReceived = false;
                        int iRet = 0;
                        if (m_fnSslDecode == nullptr || (iRet = m_fnSslDecode(reinterpret_cast<const uint8_t*>(&buf[0]), transferred, bZeroReceived), iRet == 0))
                        {
                            if (s_fTrafficDebug != nullptr)
                                s_fTrafficDebug(static_cast<uint16_t>(m_fSock), &buf[0], transferred, false);

                            auto tmp = make_unique<uint8_t[]>(transferred);
                            copy_n(&buf[0], transferred, &tmp[0]);
                            lock_guard<mutex> lock(m_mxInDeque);
                            m_quInData.emplace_back(move(tmp), transferred);
                            m_atInBytes += transferred;
                        }

                        if ((m_fBytesReceived || m_fBytesReceivedParam) && m_bStop == false && iRet != -1)
                        {
                            lock_guard<mutex> lock(mxNotify);
                            if (bReadCall == false)
                            {
                                bReadCall = true;
                                thread([&]()
                                {
                                    mxNotify.lock();
                                    m_mxInDeque.lock();
                                    while (m_atInBytes > 0 && m_bStop == false)
                                    {
                                        m_mxInDeque.unlock();
                                        mxNotify.unlock();
                                        TcpSocket* pTcpSocket = dynamic_cast<TcpSocket*>(m_pBkRef);
                                        if (m_fBytesReceivedParam != nullptr && pTcpSocket != nullptr)
                                            m_fBytesReceivedParam(pTcpSocket, m_pvUserData);
                                        else if (m_fBytesReceived != nullptr && pTcpSocket != nullptr)
                                            m_fBytesReceived(pTcpSocket);
                                        mxNotify.lock();
                                        m_mxInDeque.lock();
                                    }
                                    bReadCall = false;
                                    m_mxInDeque.unlock();
                                    mxNotify.unlock();
                                }).detach();
                            }
                        }

                        if (bZeroReceived == true)
                        {
                            if (::shutdown(m_fSock, SD_RECEIVE) != 0)
                            {
                                m_iError = WSAGetLastError();// OutputDebugString(L"Error shutdown socket\r\n");
                                m_iErrLoc = 14;
                            }
                            bSocketShutDown = true;

                            while (bReadCall == true)
                                this_thread::sleep_for(chrono::milliseconds(10));

                            TcpSocket* pTcpSocket = dynamic_cast<TcpSocket*>(m_pBkRef);
                            if (m_fBytesReceivedParam && pTcpSocket != nullptr)
                                m_fBytesReceivedParam(pTcpSocket, m_pvUserData);
                            else if (m_fBytesReceived && pTcpSocket != nullptr)
                                m_fBytesReceived(pTcpSocket);
                        }
                    }
                } while (m_bStop == false && m_fSock != INVALID_SOCKET && m_iError == 0 && bSocketShutDown == false);

                if (bSocketShutDown == true || (m_iError != 0 && m_iError != WSAEWOULDBLOCK) || m_fSock == INVALID_SOCKET)
                    break;
            }
        }// if select
    }//while

    // if we are here, bStop is set,or m_iShutDownState has bit 1 set, or we have an error

    if (bSocketShutDown == false && m_iError == 0 && m_fSock != INVALID_SOCKET)
    {
        if (::shutdown(m_fSock, SD_RECEIVE) != 0)
        {
            m_iError = WSAGetLastError();// OutputDebugString(L"Error RECEIVE shutdown socket\r\n");
            m_iErrLoc = 8;
        }
    }

    while (bReadCall == true)
        this_thread::sleep_for(chrono::milliseconds(10));

    mxNotify.lock();    // in rare cases, bReadCall was set to false, and the task switch
    mxNotify.unlock();  // ended that thread before the lambda thread released mxNotify -> crash

    m_iShutDownState |= 1;

    unsigned char cExpected = 7;
    if (m_iShutDownState.compare_exchange_strong(cExpected, 15) == true)
    {
        if (m_fSock != INVALID_SOCKET)
        {
            ::closesocket(m_fSock);
            m_fSock = INVALID_SOCKET;
        }

        StartClosingCB();

        // if it is a auto-delete class we start the auto-delete thread now
        if (m_pRefServSocket != nullptr || m_bSelfDelete == true)    // Auto-delete, socket created from server socket
             Delete();// thread([&]() { delete this; }).detach();
    }
}

void TcpSocketImpl::ConnectThread()
{
    m_iShutDownState &= static_cast<uint8_t>(~4);

    while (m_bStop == false)
    {
        fd_set writefd{}, errorfd{};
        struct timeval timeout{};

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        FD_ZERO(&writefd);
        FD_ZERO(&errorfd);

        FD_SET(m_fSock, &writefd);
        FD_SET(m_fSock, &errorfd);

        if (::select(static_cast<int>(m_fSock + 1), nullptr, &writefd, &errorfd, &timeout) > 0 && m_bStop == false)
        {
            if (FD_ISSET(m_fSock, &errorfd))
            {
                socklen_t iLen = sizeof(m_iError);
                getsockopt(m_fSock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&m_iError), &iLen);
                m_iErrLoc = 9;
                m_iShutDownState = 15;
                if (m_fErrorParam && m_bStop == false)
                    m_fErrorParam(m_pBkRef, m_pvUserData);
                else if (m_fError && m_bStop == false)
                    m_fError(m_pBkRef);
                break;
            }

            if (FD_ISSET(m_fSock, &writefd))
            {
                GetConnectionInfo();

                m_thListen = thread(&TcpSocketImpl::SelectThread, this);
                m_thWrite = thread(&TcpSocketImpl::WriteThread, this);

                TcpSocket* pTcpSocket = dynamic_cast<TcpSocket*>(m_pBkRef);
                if (m_fClientConnectedParam && pTcpSocket != nullptr)
                    m_fClientConnectedParam(pTcpSocket, m_pvUserData);
                else if (m_fClientConnected && pTcpSocket != nullptr)
                    m_fClientConnected(pTcpSocket);

                if (m_fClientConnectedSsl)
                    m_fClientConnectedSsl(nullptr);
                break;
            }
        }
    }

    m_iShutDownState |= 4;

    unsigned char cExpected = 7;
    if (m_iShutDownState.compare_exchange_strong(cExpected, 15) == true)
    {
        if (m_fSock != INVALID_SOCKET)
        {
            ::closesocket(m_fSock);
            m_fSock = INVALID_SOCKET;
        }

        StartClosingCB();

        if (m_bSelfDelete == true)    // Auto-delete, socket created from server socket
            Delete();// thread([&]() { delete this; }).detach();
    }
}

bool TcpSocketImpl::GetConnectionInfo()
{
    struct sockaddr_storage addrCl;
    socklen_t addLen = sizeof(addrCl);
    if (::getpeername(m_fSock, reinterpret_cast<struct sockaddr*>(&addrCl), &addLen) != 0)  // Get the IP to where the connection was established
    {
        m_iError = WSAGetLastError();
        m_iErrLoc = 10;
        return false;
    }

    struct sockaddr_storage addrPe;
    addLen = sizeof(addrPe);
    if (::getsockname(m_fSock, reinterpret_cast<struct sockaddr*>(&addrPe), &addLen) != 0)  // Get our IP where the connection was established
    {
        m_iError = WSAGetLastError();
        m_iErrLoc = 11;
        return false;
    }

    string caAddrClient(INET6_ADDRSTRLEN + 1, 0);
    string servInfoClient(NI_MAXSERV, 0);
    if (::getnameinfo(reinterpret_cast<struct sockaddr*>(&addrCl), sizeof(struct sockaddr_storage), &caAddrClient[0], INET6_ADDRSTRLEN, &servInfoClient[0], NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV) == 0)
    {
        m_strClientAddr = &caAddrClient[0];
        m_sClientPort = static_cast<uint16_t>(stoi(&servInfoClient[0]));
    }
    else
    {
        m_iError = WSAGetLastError();
        m_iErrLoc = 12;
        return false;
    }

    string caAddrPeer(INET6_ADDRSTRLEN + 1, 0);
    string servInfoPeer(NI_MAXSERV, 0);
    if (::getnameinfo(reinterpret_cast<struct sockaddr*>(&addrPe), sizeof(struct sockaddr_storage), &caAddrPeer[0], INET6_ADDRSTRLEN, &servInfoPeer[0], NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV) == 0)
    {
        m_strIFaceAddr = &caAddrPeer[0];
        m_sIFacePort = static_cast<uint16_t>(stoi(&servInfoPeer[0]));
    }
    else
    {
        m_iError = WSAGetLastError();
        m_iErrLoc = 13;
        return false;
    }

    return true;
}

//************************************************************************************

TcpServerImpl::TcpServerImpl(BaseSocket* pBkRef) noexcept
{
    m_pBkRef = pBkRef;
}

TcpServerImpl::~TcpServerImpl()
{
    m_fNewConnection = nullptr;
    m_bStop = true; // Stops the listening thread

    if (m_thListen.joinable() == true)
        m_thListen.join();
    Delete();
}

bool TcpServerImpl::Start(const char* const szIpAddr, const uint16_t sPort)
{
    struct addrinfo *lstAddr{}, hint{};
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_PASSIVE;

    if (::getaddrinfo(szIpAddr, to_string(sPort).c_str(), &hint, &lstAddr) != 0)
        return false;

    bool bRet = true;

    try
    {
        for (auto curAddr = lstAddr; curAddr != nullptr; curAddr = curAddr->ai_next)
        {
            const SOCKET fd = ::socket(curAddr->ai_family, curAddr->ai_socktype, curAddr->ai_protocol);
            if (fd == INVALID_SOCKET)
                throw WSAGetLastError();

            m_vSock.push_back(fd);

            SetSocketOption(fd);

            if (curAddr->ai_family == AF_INET6)
            {
                constexpr uint32_t on = 1;
                if (::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&on), sizeof(on)) == -1)
                    throw WSAGetLastError();
            }

            if (::bind(fd, curAddr->ai_addr, static_cast<int>(curAddr->ai_addrlen)) < 0)
                throw WSAGetLastError();    // https://docs.microsoft.com/de-de/troubleshoot/windows-server/backup-and-storage/error-10013-wsaeacces-is-returned
        }                                   // netsh int ipv4 show excludedportrange protocol = tcp

        for (auto fSock : m_vSock)
        {
            if (::listen(fSock, SOMAXCONN) < 0)
                throw WSAGetLastError();
        }

        m_bStop = false;
        m_thListen = thread(&TcpServerImpl::SelectThread, this);
    }

    catch (const int iSocketErr)
    {
        m_iError = iSocketErr;
        m_iErrLoc = 1;
        Delete();
        bRet = false;
    }

    ::freeaddrinfo(lstAddr);

    return bRet;
}

uint16_t TcpServerImpl::GetServerPort()
{
    struct sockaddr_storage addrPe{};
    socklen_t addLen = sizeof(addrPe);
    if (::getsockname(m_vSock[0], reinterpret_cast<struct sockaddr*>(&addrPe), &addLen) == 0)  // Get our IP where the connection was established
    {
        string caAddrPeer(INET6_ADDRSTRLEN + 1, 0);
        string servInfoPeer(NI_MAXSERV, 0);
        if (::getnameinfo(reinterpret_cast<struct sockaddr*>(&addrPe), sizeof(struct sockaddr_storage), &caAddrPeer[0], INET6_ADDRSTRLEN, &servInfoPeer[0], NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV) == 0)
        {
            return static_cast<uint16_t>(stoi(&servInfoPeer[0]));
        }
    }

    return 0;
}

void TcpServerImpl::Close() noexcept
{
    m_fNewConnection = nullptr;
    m_bStop = true; // Stops the listening thread, deletes all Sockets at the end of the listening thread
}

void TcpServerImpl::SetSocketOption(const SOCKET& fd)
{
    BaseSocketImpl::SetSocketOption(fd);

    constexpr SOCKOPT rc = 1;
    if (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &rc, sizeof(rc)) == -1)
        throw WSAGetLastError();
}

TcpSocket* TcpServerImpl::MakeClientConnection(const SOCKET& fSock)
{
    unique_ptr<BaseSocket> pTcpSocket = make_unique<TcpSocket>();
    TcpSocket* pTcpSock = dynamic_cast<TcpSocket*>(pTcpSocket.get());
    TcpSocketImpl* pTcpSocketImpl = dynamic_cast<TcpSocketImpl*>(pTcpSock->GetImpl());

    try
    {
        pTcpSocketImpl->m_fSock = fSock;
        pTcpSocketImpl->m_iShutDownState = 7;
        pTcpSocketImpl->m_pRefServSocket = dynamic_cast<TcpServer*>(m_pBkRef);
        pTcpSocketImpl->m_thWrite = thread(&TcpSocketImpl::WriteThread, dynamic_cast<TcpSocketImpl*>(pTcpSock->GetImpl()));

        pTcpSocketImpl->SetSocketOption(fSock);
        pTcpSocketImpl->GetConnectionInfo();
    }

    catch (const int iErrNo)
    {
        pTcpSocketImpl->SetErrorNo(iErrNo);
    }

    lock_guard<mutex> lock(s_mxClientSocket);
    s_lstClientSocket.push_back(move(pTcpSocket));

    return pTcpSock;
}

void TcpServerImpl::BindNewConnection(function<void(const vector<TcpSocket*>&)> fNewConnection) noexcept
{
    m_fNewConnection.swap(fNewConnection);
}

void TcpServerImpl::BindNewConnection(function<void(const vector<TcpSocket*>&, void*)> fNewConnection) noexcept
{
    m_fNewConnectionParam.swap(fNewConnection);
}

void TcpServerImpl::Delete()
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

void TcpServerImpl::SelectThread()
{
    atomic<uint32_t> nNewConCbCount(0);

    while (m_bStop == false)
    {
        fd_set readfd{};
        struct timeval timeout{};
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

        const int iRes = ::select(static_cast<int>(maxFd + 1), &readfd, nullptr, nullptr, &timeout);
        if (iRes > 0)
        {
            vector<SOCKET> vSockets;

            for (auto Sock : m_vSock)
            {
                if (FD_ISSET(Sock, &readfd))
                {
                    for (int n = 0; n < 16; ++n)                // The ACCEPT_QUEUE is an optimization mechanism that allows the server to
                    {                                           // accept() up to this many connections before serving any of them.  The
                        struct sockaddr_storage addrCl;         // reason is that the timeout waiting for the accept() is much shorter
                        socklen_t addLen = sizeof(addrCl);      // than the timeout for the actual processing.

                        const SOCKET fdClient = ::accept(Sock, reinterpret_cast<struct sockaddr*>(&addrCl), &addLen);
                        if (fdClient == INVALID_SOCKET)
                            break;

                        vSockets.push_back(fdClient);
                    }
                }
            }

            if (vSockets.size() > 0 && m_bStop == false)
            {
                nNewConCbCount++;

                thread([this, &nNewConCbCount](const vector<SOCKET> vNewSockets)
                {
                    vector<TcpSocket*> vNewConnections;
                    for (const SOCKET sock : vNewSockets)
                    {
                        TcpSocket* pClient = MakeClientConnection(sock);
                        if (pClient == nullptr)
                            continue;
                        if (pClient->GetErrorNo() != 0)
                        {
                            if (m_fErrorParam)
                                m_fErrorParam(pClient, m_pvUserData);  // Must call Close() in the error callback
                            else if (m_fError)
                                m_fError(pClient);  // Must call Close() in the error callback
                            else
                                pClient->Close();
                            continue;
                        }
                        vNewConnections.push_back(pClient);
                    }
                    if (m_fNewConnectionParam != nullptr && m_bStop != true)
                        m_fNewConnectionParam(vNewConnections, m_pvUserData);
                    else if (m_fNewConnection != nullptr && m_bStop != true)
                        m_fNewConnection(vNewConnections);
                    else
                    {
                        for (auto pClient : vNewConnections)
                            pClient->Close();
                    }
                    nNewConCbCount--;
                }, vSockets).detach();
            }
        }
    }

    while (nNewConCbCount != 0)
        this_thread::sleep_for(chrono::milliseconds(1));

    Delete();
}

//********************************************************************************

UdpSocketImpl::UdpSocketImpl(BaseSocket* pBkRef) : m_bCloseReq(false)
{
    atomic_init(&m_atInBytes, static_cast<size_t>(0));
    atomic_init(&m_atOutBytes, static_cast<size_t>(0));
    m_pBkRef = pBkRef;
}

UdpSocketImpl::~UdpSocketImpl()
{
    m_bStop = true; // Stops the listening thread
    const bool bIsLocked = m_mxWrite.try_lock();
    m_bCloseReq = true;
    m_atOutBytes = 0;
    m_cv.notify_all();
    if (bIsLocked == true)
        m_mxWrite.unlock();

    if (m_fSock != INVALID_SOCKET)
    {
        ::closesocket(m_fSock);

        if (m_fClosingParam)
            m_fClosingParam(m_pBkRef, m_pvUserData);
        else if (m_fClosing)
            m_fClosing(m_pBkRef);
    }
}

bool UdpSocketImpl::Create(const char* const szIpToWhere, const uint16_t sPort, const char* const szIpToBind/* = nullptr*/)
{
    struct addrinfo* lstAddr{}, hint{};
    hint.ai_family = AF_UNSPEC;
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
            constexpr uint32_t on = 0;
            if (::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&on), sizeof(on)) == -1)
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

        m_thListen = thread(&UdpSocketImpl::SelectThread, this);
        m_thWrite = thread(&UdpSocketImpl::WriteThread, this);
    }

    catch (const int iSocketErr)
    {
        m_iError = iSocketErr;
        m_iErrLoc = 1;
        if (m_fSock != INVALID_SOCKET)
            ::closesocket(m_fSock);
        m_fSock = INVALID_SOCKET;

        bRet = false;
    }

    ::freeaddrinfo(lstAddr);

    return bRet;
}

bool UdpSocketImpl::EnableBroadCast(bool bEnable/* = true*/) noexcept
{
    const int iBroadcast = bEnable == true ? 1 : 0;
    if (::setsockopt(m_fSock, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&iBroadcast), sizeof(int)) == SOCKET_ERROR)
        return false;
    return true;
}

#if defined(_WIN32) || defined(_WIN64)
bool UdpSocketImpl::AddToMulticastGroup(const char* const szMulticastIp, const char* const/*szInterfaceIp*/, uint32_t nInterfaceIndex) noexcept
#else
bool UdpSocketImpl::AddToMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex) noexcept
#endif
{
    struct addrinfo *lstAddr;
    if (::getaddrinfo(szMulticastIp, nullptr, nullptr, &lstAddr) != 0)
        return false;
    const int iAddFamily = lstAddr->ai_family;
    ::freeaddrinfo(lstAddr);

    constexpr uint32_t hops = static_cast<uint8_t>('\xff');
    constexpr uint32_t loop = 1;

    if (iAddFamily == AF_INET6)
    {
        ipv6_mreq mreq{IN6ADDR_ANY_INIT, 0};
        inet_pton(AF_INET6, szMulticastIp, &mreq.ipv6mr_multiaddr);
        mreq.ipv6mr_interface = nInterfaceIndex;

        // http://www.tldp.org/HOWTO/Multicast-HOWTO-6.html
        if (::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, reinterpret_cast<char*>(&mreq), sizeof(mreq)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, reinterpret_cast<const char*>(&hops), sizeof(hops)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, reinterpret_cast<const char*>(&loop), sizeof(loop)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_MULTICAST_IF, reinterpret_cast<char*>(&mreq.ipv6mr_interface), sizeof(mreq.ipv6mr_interface)) != 0)
        {
            m_iError = WSAGetLastError();
            m_iErrLoc = 2;
            return false;
        }
    }
    else
    {
        ip_mreq mreq{{0},{0}};
        inet_pton(AF_INET, szMulticastIp, &mreq.imr_multiaddr.s_addr);
#if defined(_WIN32) || defined(_WIN64)
        mreq.imr_interface.s_addr = htonl(nInterfaceIndex);
#else
        inet_pton(AF_INET, szInterfaceIp, &mreq.imr_interface.s_addr);
#endif

        if (::setsockopt(m_fSock, IPPROTO_IP, IP_ADD_MEMBERSHIP, reinterpret_cast<char*>(&mreq), sizeof(mreq)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char*>(&hops), sizeof(hops)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IP, IP_MULTICAST_LOOP, reinterpret_cast<const char*>(&loop), sizeof(loop)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IP, IP_MULTICAST_IF, reinterpret_cast<char*>(&mreq.imr_interface), sizeof(mreq.imr_interface)) != 0)
        {
            m_iError = WSAGetLastError();
            m_iErrLoc = 2;
            return false;
        }
    }

    return true;
}

#if defined(_WIN32) || defined(_WIN64)
bool UdpSocketImpl::RemoveFromMulticastGroup(const char* const szMulticastIp, const char* const/*szInterfaceIp*/, uint32_t nInterfaceIndex) noexcept
#else
bool UdpSocketImpl::RemoveFromMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex) noexcept
#endif
{
    struct addrinfo *lstAddr;
    if (::getaddrinfo(szMulticastIp, nullptr, nullptr, &lstAddr) != 0)
        return false;
    const int iAddFamily = lstAddr->ai_family;
    ::freeaddrinfo(lstAddr);

    constexpr uint32_t AnyAddr = INADDR_ANY;

    if (iAddFamily == AF_INET6)
    {
        ipv6_mreq mreq{IN6ADDR_ANY_INIT, 0};
        inet_pton(AF_INET6, szMulticastIp, &mreq.ipv6mr_multiaddr);
        mreq.ipv6mr_interface = nInterfaceIndex; // use default

        if (::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, reinterpret_cast<char*>(&mreq), sizeof(mreq)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IPV6, IPV6_MULTICAST_IF, reinterpret_cast<const char*>(&AnyAddr), sizeof(uint32_t)) != 0)
        {
            m_iError = WSAGetLastError();
            m_iErrLoc = 3;
            return false;
        }
    }
    else
    {
        ip_mreq mreq{{0},{0}};
        inet_pton(AF_INET, szMulticastIp, &mreq.imr_multiaddr.s_addr);
#if defined(_WIN32) || defined(_WIN64)
        mreq.imr_interface.s_addr = htonl(nInterfaceIndex);
#else
        inet_pton(AF_INET, szInterfaceIp, &mreq.imr_interface.s_addr);
#endif

        if (setsockopt(m_fSock, IPPROTO_IP, IP_DROP_MEMBERSHIP, reinterpret_cast<char *>(&mreq), sizeof(mreq)) != 0
        || ::setsockopt(m_fSock, IPPROTO_IP, IP_MULTICAST_IF, reinterpret_cast<const char*>(&AnyAddr), sizeof(uint32_t)) != 0)
        {
            m_iError = WSAGetLastError();
            m_iErrLoc = 3;
            return false;
        }
    }

    return true;
}

size_t UdpSocketImpl::Read(void* buf, size_t len, string& strFrom)
{
    if (m_atInBytes == 0 || buf == nullptr || len == 0)
        return 0;

    size_t nOffset = 0;
    size_t nRet = 0;

    m_mxInDeque.lock();
    DATA data = move(m_quInData.front());
    m_quInData.pop_front();
    m_mxInDeque.unlock();

    // Copy the data into the destination buffer
    const size_t nToCopy = min(BUFLEN(data), len);
    copy_n(&BUFFER(data)[0], nToCopy, &static_cast<uint8_t*>(buf)[nOffset]);
    m_atInBytes -= nToCopy;
    strFrom = ADDRESS(data);
    nRet += nToCopy;

    if (nToCopy < BUFLEN(data))
    {   // Put the Rest of the Data back to the Que
        size_t nRest = BUFLEN(data) - nToCopy;
        auto tmp = make_unique<uint8_t[]>(nRest);
        copy_n(&BUFFER(data)[nToCopy], nToCopy + nRest, &tmp[0]);
        m_mxInDeque.lock();
        m_quInData.emplace_front(move(tmp), nRest, ADDRESS(data));
        m_mxInDeque.unlock();
    }

    return nRet;
}

void UdpSocketImpl::TriggerWriteThread()
{
    unique_lock<mutex> lock(m_mxWrite);
    m_cv.notify_all();
}

size_t UdpSocketImpl::Write(const void* buf, size_t len, const string& strTo)
{
    if (m_bStop == true || m_bCloseReq == true || buf == nullptr || len == 0 || strTo.empty() == true)
        return 0;

    int iRet = 0;
    if (m_fnSslEncode == nullptr || (iRet = m_fnSslEncode(reinterpret_cast<const uint8_t*>(buf), len, strTo), iRet == 0))
    {
        auto tmp = make_unique<uint8_t[]>(len);
        copy_n(&static_cast<const uint8_t*>(buf)[0], len, &tmp[0]);
        m_mxOutDeque.lock();
        m_atOutBytes += len;
        m_quOutData.emplace_back(move(tmp), len, strTo);
        m_mxOutDeque.unlock();

        iRet = 1;   // Trigger WriteThread
    }

    if (iRet > 0)
        TriggerWriteThread();

    return len;
}

void UdpSocketImpl::WriteThread()
{

    unique_lock<mutex> lock(m_mxWrite);

    while (m_bCloseReq == false || m_atOutBytes != 0)
    {
        if (m_bCloseReq == false && m_atOutBytes == 0)
            m_cv.wait(lock, [&]() noexcept { return m_atOutBytes == 0 ? m_bCloseReq : true; });

        if (m_atOutBytes != 0)
        {
            fd_set writefd{}, errorfd{};
            struct timeval timeout{};

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            FD_ZERO(&writefd);
            FD_ZERO(&errorfd);

            FD_SET(m_fSock, &writefd);
            FD_SET(m_fSock, &errorfd);

            if (::select(static_cast<int>(m_fSock + 1), nullptr, &writefd, &errorfd, &timeout) == 0)
            {
                if (m_bCloseReq == false) continue;
                break;
            }

            if (FD_ISSET(m_fSock, &errorfd))
            {
                if (m_iError == 0)
                {
                    socklen_t iLen = sizeof(m_iError);
                    getsockopt(m_fSock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&m_iError), &iLen);
                    m_iErrLoc = 5;
                    if (m_fErrorParam && m_bStop == false)
                        m_fErrorParam(m_pBkRef, m_pvUserData);
                    else if (m_fError && m_bStop == false)
                        m_fError(m_pBkRef);
                }
                break;
            }

            m_mxOutDeque.lock();
            DATA data = move(m_quOutData.front());
            m_quOutData.pop_front();
            m_atOutBytes -= BUFLEN(data);
            m_mxOutDeque.unlock();

            struct addrinfo *lstAddr = nullptr;
            const size_t nPosS = ADDRESS(data).find('[');
            const size_t nPosE = ADDRESS(data).find(']');
            if (nPosS != string::npos && nPosE != string::npos)
            {
                if (::getaddrinfo(ADDRESS(data).substr(nPosS + 1, nPosE - 1).c_str(), ADDRESS(data).substr(nPosE + 2).c_str(), nullptr, &lstAddr) != 0)
                    break;    // we return 0, because of a wrong address
            }
            else
            {
                const size_t nPos = ADDRESS(data).find(':');
                if (nPos != string::npos)
                {
                    if (::getaddrinfo(ADDRESS(data).substr(0, nPos).c_str(), ADDRESS(data).substr(nPos + 1).c_str(), nullptr, &lstAddr) != 0)
                        break;    // we return 0, because of a wrong address
                }
                else
                    break;    // we return 0, because of a wrong address
            }

            const uint32_t transferred = ::sendto(m_fSock, reinterpret_cast<const char*>(&BUFFER(data)[0]), static_cast<int>(BUFLEN(data)), 0, lstAddr->ai_addr, static_cast<int>(lstAddr->ai_addrlen));
            ::freeaddrinfo(lstAddr);
            if (static_cast<int32_t>(transferred) <= 0)
            {
                m_iError = WSAGetLastError();
                if (m_iError != WSAEWOULDBLOCK)
                {
                    m_iErrLoc = 6;
                    if (m_fErrorParam && m_bStop == false)
                        m_fErrorParam(m_pBkRef, m_pvUserData);
                    else if (m_fError && m_bStop == false)
                        m_fError(m_pBkRef);
                    break;
                }
                // Put the not send bytes back into the que if it is not a SSL connection. A SSL connection has the bytes still available
                auto tmp = make_unique<uint8_t[]>(BUFLEN(data));
                copy_n(&BUFFER(data)[0], BUFLEN(data), &tmp[0]);
                m_mxOutDeque.lock();
                m_atOutBytes += BUFLEN(data);
                m_quOutData.emplace_front(move(tmp), BUFLEN(data), ADDRESS(data));
                m_mxOutDeque.unlock();
            }
            else if (transferred < BUFLEN(data)) // Less bytes send as buffer size, we put the rast back in your que
            {
                auto tmp = make_unique<uint8_t[]>(BUFLEN(data) - transferred);
                copy_n(&BUFFER(data)[transferred], BUFLEN(data) - transferred, &tmp[0]);
                m_mxOutDeque.lock();
                m_atOutBytes += (BUFLEN(data) - transferred);
                m_quOutData.emplace_front(move(tmp), (BUFLEN(data) - transferred), ADDRESS(data));
                m_mxOutDeque.unlock();
            }
        }
    }

    lock.unlock();

    // if we get out of the while loop, the stop request was send or we have an error
    if (m_iError == 0)
    {
        if (::shutdown(m_fSock, SD_SEND) != 0)
        {
            m_iError = WSAGetLastError();// OutputDebugString(L"Error shutdown socket\r\n");
            m_iErrLoc = 4;
        }
    }
    m_iShutDownState |= 2;

    unsigned char cExpected = 3;
    if (m_iShutDownState.compare_exchange_strong(cExpected, 15) == true)
    {
        if (m_fSock != INVALID_SOCKET)
            ::closesocket(m_fSock);
        m_fSock = INVALID_SOCKET;

        if (m_fClosing || m_fClosingParam)
            StartClosingCB();
    }
}

void UdpSocketImpl::Close()
{
    m_bCloseReq = true; // Stops the write thread after the last byte was send
    do
    {
        const bool bIsLocked = m_mxWrite.try_lock();
        m_cv.notify_all();
        if (bIsLocked == true)
            m_mxWrite.unlock();
    } while ((m_iShutDownState & 2) == 0 && m_iError == 0); // Wait until the write thread is finished
    m_bStop = true; // Stops the listening thread
}

size_t UdpSocketImpl::GetBytesAvailable() const noexcept
{
    return m_atInBytes;
}

size_t UdpSocketImpl::GetOutBytesInQue() const noexcept
{
    return m_atOutBytes;
}

function<void(UdpSocket*)> UdpSocketImpl::BindFuncBytesReceived(function<void(UdpSocket*)> fBytesReceived) noexcept
{
    m_fBytesReceived.swap(fBytesReceived);
    return fBytesReceived;
}

function<void(UdpSocket*, void*)> UdpSocketImpl::BindFuncBytesReceived(function<void(UdpSocket*, void*)> fBytesReceived) noexcept
{
    m_fBytesReceivedParam.swap(fBytesReceived);
    return fBytesReceived;
}

void UdpSocketImpl::SelectThread()
{
    bool bReadCall = false;
    mutex mxNotify;
    bool bSocketShutDown = false;
	auto buf = make_unique<char[]>(0x0000ffff);

    while (m_bStop == false)
    {
        if (m_atInBytes > 0x40000)  // More than 256 KB in the receive buffer
        {
            this_thread::sleep_for(chrono::milliseconds(1));
            continue;
        }

        fd_set readfd{}, errorfd{};
        struct timeval timeout{};

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
                m_iErrLoc = 7;
                if (m_fErrorParam && m_bStop == false)
                    m_fErrorParam(m_pBkRef, m_pvUserData);
                else if (m_fError && m_bStop == false)
                    m_fError(m_pBkRef);
                break;
            }

            if (FD_ISSET(m_fSock, &readfd))
            {
                union
                {
                    sockaddr_in sin;
                    sockaddr_in6 sin6;
                }SenderAddr;
                socklen_t sinLen = sizeof(SenderAddr);

                int32_t transferred = ::recvfrom(m_fSock, &buf[0], 0x0000ffff, 0, reinterpret_cast<sockaddr*>(&SenderAddr), &sinLen);

                if (transferred <= 0)
                {
                    if (transferred == 0)
                    {   // The connection was shutdown from the other side, there will be no more bytes to read on that connection
                        // We set the flag, so we don't read on the connection any more
                        if (::shutdown(m_fSock, SD_RECEIVE) != 0)
                        {
                            m_iError = WSAGetLastError();// OutputDebugString(L"Error shutdown socket\r\n");
                            m_iErrLoc = 9;
                        }
                        bSocketShutDown = true;

                        while (bReadCall == true)
                            this_thread::sleep_for(chrono::milliseconds(10));

                        UdpSocket* pUdpSocket = dynamic_cast<UdpSocket*>(m_pBkRef);
                        if (m_fBytesReceivedParam && pUdpSocket != nullptr)
                            m_fBytesReceivedParam(pUdpSocket, m_pvUserData);
                        else if (m_fBytesReceived && pUdpSocket != nullptr)
                            m_fBytesReceived(pUdpSocket);
                        break;
                    }
                    else
                    {
                        m_iError = WSAGetLastError();
                        if (m_iError != WSAEWOULDBLOCK)
                        {
                            m_iErrLoc = 11;
                            if (m_fErrorParam && m_bStop == false)
                                m_fErrorParam(m_pBkRef, m_pvUserData);
                            else if (m_fError && m_bStop == false)
                                m_fError(m_pBkRef);
                            break;
                        }
                    }
                }
                else
                {
                    stringstream strAbsender;
                    string caAddrBuf(INET6_ADDRSTRLEN + 1, 0);
                    if (SenderAddr.sin6.sin6_family == AF_INET6)
                    {
                        strAbsender << "[" << inet_ntop(SenderAddr.sin6.sin6_family, &SenderAddr.sin6.sin6_addr, &caAddrBuf[0], sizeof(caAddrBuf));
                        strAbsender << "]:" << ntohs(SenderAddr.sin6.sin6_port);
                    }
                    else
                    {
                        strAbsender << inet_ntop(SenderAddr.sin.sin_family, &SenderAddr.sin.sin_addr, &caAddrBuf[0], sizeof(caAddrBuf));
                        strAbsender << ":" << ntohs(SenderAddr.sin.sin_port);
                    }

                    int iRet = 0;
                    if (m_fnSslDecode == nullptr || (iRet = m_fnSslDecode(reinterpret_cast<uint8_t*>(&buf[0]), transferred, strAbsender.str()), iRet == 0))
                    {
                        auto tmp = make_unique<uint8_t[]>(transferred);
                        copy_n(&buf[0], transferred, &tmp[0]);
                        m_mxInDeque.lock();
                        m_quInData.emplace_back(move(tmp), transferred, strAbsender.str());
                        m_atInBytes += transferred;
                        m_mxInDeque.unlock();
                    }

                    if ((m_fBytesReceived || m_fBytesReceivedParam) && m_bStop == false && iRet != -1)
                    {
                        lock_guard<mutex> lock(mxNotify);
                        if (bReadCall == false)
                        {
                            bReadCall = true;
                            thread([&]()
                            {
                                mxNotify.lock();
                                while (m_atInBytes > 0 && m_bStop == false)
                                {
                                    UdpSocket* pUdpSocket = dynamic_cast<UdpSocket*>(m_pBkRef);
                                    mxNotify.unlock();
                                    if (m_fBytesReceivedParam != nullptr && pUdpSocket != nullptr)
                                        m_fBytesReceivedParam(pUdpSocket, m_pvUserData);
                                    else if (pUdpSocket != nullptr)
                                        m_fBytesReceived(pUdpSocket);
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
        {
            m_iError = WSAGetLastError();// OutputDebugString(L"Error RECEIVE shutdown socket\r\n");
            m_iErrLoc = 10;
        }
    }

    while (bReadCall == true)
        this_thread::sleep_for(chrono::milliseconds(10));

    mxNotify.lock();    // In rare cases, bReadCall was set to false, and the task switch
    mxNotify.unlock();  // ended that thread before the lambda thread released mxNotify -> crash

    m_iShutDownState |= 1;

    unsigned char cExpected = 3;
    if (m_iShutDownState.compare_exchange_strong(cExpected, 15) == true)
    {
        if (m_fSock != INVALID_SOCKET)
            ::closesocket(m_fSock);
        m_fSock = INVALID_SOCKET;

        if (m_fClosing || m_fClosingParam)
            StartClosingCB();
    }
}
