/* Copyright (C) 2016-2020 Thomas Hauck - All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT

   The author would be happy if changes and
   improvements were reported back to him.

   Author:  Thomas Hauck
   Email:   Thomas@fam-hauck.de
*/

#include "SocketLib.h"
#include "StdSocket.h"
#include "SslSocket.h"

using namespace std::placeholders;


BaseSocket::BaseSocket(BaseSocketImpl* pImpl) noexcept : Impl_(pImpl)
{

}
BaseSocket::~BaseSocket() = default;

void BaseSocket::SetImpl(BaseSocketImpl* pImpl) noexcept
{
    Impl_.reset(pImpl);
}

BaseSocketImpl* BaseSocket::GetImpl() const noexcept
{
    return Impl_.get();
}

int BaseSocket::GetErrorNo() const  noexcept
{
    return GetImpl()->GetErrorNo();
}

int BaseSocket::GetErrorLoc() const  noexcept
{
    return GetImpl()->GetErrorLoc();
}

function<void(BaseSocket*)> BaseSocket::BindErrorFunction(function<void(BaseSocket*)> fError)
{
    return GetImpl()->BindErrorFunction(fError);
}

function<void(BaseSocket*, void*)> BaseSocket::BindErrorFunction(function<void(BaseSocket*, void*)> fError)
{
    return GetImpl()->BindErrorFunction(fError);
}

function<void(BaseSocket*)> BaseSocket::BindCloseFunction(function<void(BaseSocket*)> fCloseing)
{
    return GetImpl()->BindCloseFunction(fCloseing);
}

function<void(BaseSocket*, void*)> BaseSocket::BindCloseFunction(function<void(BaseSocket*, void*)> fCloseing)
{
    return GetImpl()->BindCloseFunction(fCloseing);
}

void BaseSocket::SetCallbackUserData(void* pUserData) noexcept
{
    GetImpl()->SetCallbackUserData(pUserData);
}

void BaseSocket::SetErrorNo(int iErrNo) noexcept
{
    return GetImpl()->SetErrorNo(iErrNo);
}

uint16_t BaseSocket::GetSocketPort()
{
    return GetImpl()->GetSocketPort();
}

int BaseSocket::EnumIpAddresses(function<int(int, const string&, int, void*)> fnCallBack, void* vpUser)
{
    return BaseSocketImpl::EnumIpAddresses(fnCallBack, vpUser);
}

void BaseSocket::SetAddrNotifyCallback(const function<void(bool, const string&, int, int)>& fnCbAddrNotify)
{
    return BaseSocketImpl::SetAddrNotifyCallback(fnCbAddrNotify);
}

void BaseSocket::SetTraficDebugCallback(function<void(const uint16_t, const char*, size_t, bool)> fnCbTraficDbg)
{
    BaseSocketImpl::SetTraficDebugCallback(fnCbTraficDbg);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TcpSocket::TcpSocket() : BaseSocket(new TcpSocketImpl(this))
{
}

TcpSocket::TcpSocket(TcpSocketImpl* const impl) noexcept : BaseSocket(impl)
{

}

bool TcpSocket::Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint/* = AF_UNSPEC*/)
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->Connect(szIpToWhere, sPort, AddrHint);
}
size_t TcpSocket::Read(void* buf, size_t len)
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->Read(buf, len);
}
size_t TcpSocket::PutBackRead(void* buf, size_t len)
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->PutBackRead(buf, len);
}
size_t TcpSocket::Write(const void* buf, size_t len)
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->Write(buf, len);
}
void TcpSocket::StartReceiving()
{
    dynamic_cast<TcpSocketImpl*>(GetImpl())->StartReceiving();
}
void TcpSocket::Close()
{
    dynamic_cast<TcpSocketImpl*>(GetImpl())->Close();
}
void TcpSocket::SelfDestroy()
{
    dynamic_cast<TcpSocketImpl*>(GetImpl())->SelfDestroy();
}
void TcpSocket::Delete()
{
    dynamic_cast<TcpSocketImpl*>(GetImpl())->Delete();
}
size_t TcpSocket::GetBytesAvailible() const noexcept
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->GetBytesAvailible();
}
size_t TcpSocket::GetOutBytesInQue() const noexcept
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->GetOutBytesInQue();
}

function<void(TcpSocket*)> TcpSocket::BindFuncBytesReceived(function<void(TcpSocket*)> fBytesReceived)
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->BindFuncBytesReceived(fBytesReceived);
}
function<void(TcpSocket*, void*)> TcpSocket::BindFuncBytesReceived(function<void(TcpSocket*, void*)> fBytesReceived)
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->BindFuncBytesReceived(fBytesReceived);
}
function<void(TcpSocket*)> TcpSocket::BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted)
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->BindFuncConEstablished(fClientConneted);
}
function<void(TcpSocket*, void*)> TcpSocket::BindFuncConEstablished(function<void(TcpSocket*, void*)> fClientConneted)
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->BindFuncConEstablished(fClientConneted);
}

bool TcpSocket::IsSslConnection() const noexcept 
{ 
    return false; 
}

const string& TcpSocket::GetClientAddr() const noexcept
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->GetClientAddr();
}
uint16_t TcpSocket::GetClientPort() const noexcept
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->GetClientPort();
}
const string& TcpSocket::GetInterfaceAddr() const noexcept
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->GetInterfaceAddr();
}
uint16_t TcpSocket::GetInterfacePort() const noexcept
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->GetInterfacePort();
}

const TcpServer* TcpSocket::GetServerSocketRef() const noexcept
{
    return dynamic_cast<TcpSocketImpl*>(GetImpl())->GetServerSocketRef();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TcpServer::TcpServer() : BaseSocket(new TcpServerImpl(this))
{
}

TcpServer::TcpServer(TcpServerImpl* const impl) noexcept : BaseSocket(impl)
{
}

bool TcpServer::Start(const char* const szIpAddr, const uint16_t sPort)
{
    return dynamic_cast<TcpServerImpl*>(GetImpl())->Start(szIpAddr, sPort);
}
unsigned short TcpServer::GetServerPort()
{
    return dynamic_cast<TcpServerImpl*>(GetImpl())->GetServerPort();
}
void TcpServer::BindNewConnection(function<void(const vector<TcpSocket*>&)> fnNewConnection)
{
    dynamic_cast<TcpServerImpl*>(GetImpl())->BindNewConnection(fnNewConnection);
}
void TcpServer::BindNewConnection(function<void(const vector<TcpSocket*>&, void*)> fnNewConnection)
{
    dynamic_cast<TcpServerImpl*>(GetImpl())->BindNewConnection(fnNewConnection);
}
void TcpServer::Close() noexcept
{
    dynamic_cast<TcpServerImpl*>(GetImpl())->Close();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

UdpSocket::UdpSocket() : BaseSocket(new UdpSocketImpl(this))
{
}

UdpSocket::UdpSocket(UdpSocketImpl* const impl) noexcept : BaseSocket(impl)
{

}

bool UdpSocket::Create(const char* const szIpToWhere, const uint16_t sPort, const char* const szIpToBind/* = nullptr*/)
{
    return dynamic_cast<UdpSocketImpl*>(GetImpl())->Create(szIpToWhere, sPort, szIpToBind);
}

bool UdpSocket::EnableBroadCast(bool bEnable/* = true*/) noexcept
{
    return dynamic_cast<UdpSocketImpl*>(GetImpl())->EnableBroadCast(bEnable);
}

bool UdpSocket::AddToMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex) noexcept
{
    return dynamic_cast<UdpSocketImpl*>(GetImpl())->AddToMulticastGroup(szMulticastIp, szInterfaceIp, nInterfaceIndex);
}

bool UdpSocket::RemoveFromMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex) noexcept
{
    return dynamic_cast<UdpSocketImpl*>(GetImpl())->RemoveFromMulticastGroup(szMulticastIp, szInterfaceIp, nInterfaceIndex);
}

size_t UdpSocket::Read(void* buf, size_t len, string& strFrom)
{
    return dynamic_cast<UdpSocketImpl*>(GetImpl())->Read(buf, len, strFrom);
}

size_t UdpSocket::Write(const void* buf, size_t len, const string& strTo)
{
    return dynamic_cast<UdpSocketImpl*>(GetImpl())->Write(buf, len, strTo);
}

void UdpSocket::Close()
{
    dynamic_cast<UdpSocketImpl*>(GetImpl())->Close();
}

size_t UdpSocket::GetBytesAvailible() const noexcept
{
    return dynamic_cast<UdpSocketImpl*>(GetImpl())->GetBytesAvailible();
}

size_t UdpSocket::GetOutBytesInQue() const noexcept
{
    return dynamic_cast<UdpSocketImpl*>(GetImpl())->GetBytesAvailible();
}

function<void(UdpSocket*)> UdpSocket::BindFuncBytesReceived(function<void(UdpSocket*)> fBytesReceived)
{
    return dynamic_cast<UdpSocketImpl*>(GetImpl())->BindFuncBytesReceived(fBytesReceived);
}

function<void(UdpSocket*, void*)> UdpSocket::BindFuncBytesReceived(function<void(UdpSocket*, void*)> fBytesReceived)
{
    return dynamic_cast<UdpSocketImpl*>(GetImpl())->BindFuncBytesReceived(fBytesReceived);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef WITHOUT_OPENSSL

SslTcpSocket::SslTcpSocket() : TcpSocket(new SslTcpSocketImpl(this))
{
}

SslTcpSocket::SslTcpSocket(TcpSocket* pTcpSocket) : TcpSocket(new SslTcpSocketImpl(this, reinterpret_cast<TcpSocketImpl*>(pTcpSocket->GetImpl())))
{
}

SslTcpSocket::SslTcpSocket(SslTcpSocketImpl* const impl) : TcpSocket(impl)
{

}

SslTcpSocket::~SslTcpSocket()
{

}

bool SslTcpSocket::AddServerCertificat(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey, const char* szDhParamFileName)
{
    return dynamic_cast<SslTcpSocketImpl*>(GetImpl())->AddServerCertificat(szCAcertificate, szHostCertificate, szHostKey, szDhParamFileName);
}

bool SslTcpSocket::AddCertificat(const char* const szHostCertificate, const char* const szHostKey)
{
    return dynamic_cast<SslTcpSocketImpl*>(GetImpl())->AddCertificat(szHostCertificate, szHostKey);
}

bool SslTcpSocket::SetCipher(const char* const szCipher) noexcept
{
    return dynamic_cast<SslTcpSocketImpl*>(GetImpl())->SetCipher(szCipher);
}

bool SslTcpSocket::SetAcceptState()
{
    return dynamic_cast<SslTcpSocketImpl*>(GetImpl())->SetAcceptState();
}

bool SslTcpSocket::SetConnectState()
{
    return dynamic_cast<SslTcpSocketImpl*>(GetImpl())->SetConnectState();
}

bool SslTcpSocket::Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint/* = AF_UNSPEC*/)
{
    return dynamic_cast<SslTcpSocketImpl*>(GetImpl())->Connect(szIpToWhere, sPort, AddrHint);
}

void SslTcpSocket::Close()
{
    dynamic_cast<SslTcpSocketImpl*>(GetImpl())->Close();
}

function<void(TcpSocket*)> SslTcpSocket::BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted)
{
    return dynamic_cast<SslTcpSocketImpl*>(GetImpl())->BindFuncConEstablished(fClientConneted);
}

function<void(TcpSocket*, void*)> SslTcpSocket::BindFuncConEstablished(function<void(TcpSocket*, void*)> fClientConneted)
{
    return dynamic_cast<SslTcpSocketImpl*>(GetImpl())->BindFuncConEstablished(fClientConneted);
}

bool SslTcpSocket::IsSslConnection() const noexcept
{
    return true;
}

void SslTcpSocket::SetAlpnProtokollNames(const vector<string>& vProtoList)
{
    dynamic_cast<SslTcpSocketImpl*>(GetImpl())->SetAlpnProtokollNames(vProtoList);
}

const string SslTcpSocket::GetSelAlpnProtocol() const
{
    return dynamic_cast<SslTcpSocketImpl*>(GetImpl())->GetSelAlpnProtocol();
}

void SslTcpSocket::SetTrustedRootCertificates(const char* const szTrustRootCert)
{
    dynamic_cast<SslTcpSocketImpl*>(GetImpl())->SetTrustedRootCertificates(szTrustRootCert);
}

long SslTcpSocket::CheckServerCertificate(const char* const szHostName)
{
    return dynamic_cast<SslTcpSocketImpl*>(GetImpl())->CheckServerCertificate(szHostName);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

SslTcpServer::SslTcpServer() : TcpServer(new SslTcpServerImpl(this))
{
}

bool SslTcpServer::AddCertificat(const char* const szCAcertificate, const char* const szHostCertificate, const char* const szHostKey)
{
    return dynamic_cast<SslTcpServerImpl*>(GetImpl())->AddCertificat(szCAcertificate, szHostCertificate, szHostKey);
}

bool SslTcpServer::SetDHParameter(const char* const szDhParamFileName)
{
    return dynamic_cast<SslTcpServerImpl*>(GetImpl())->SetDHParameter(szDhParamFileName);
}

bool SslTcpServer::SetCipher(const char* const szCipher) noexcept
{
    return dynamic_cast<SslTcpServerImpl*>(GetImpl())->SetCipher(szCipher);
}

void SslTcpServer::SetAlpnProtokollNames(const vector<string>& vProtoList)
{
    dynamic_cast<SslTcpServerImpl*>(GetImpl())->SetAlpnProtokollNames(vProtoList);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

SslUdpSocket::SslUdpSocket() : UdpSocket(new SslUdpSocketImpl(this))
{
}

bool SslUdpSocket::AddCertificat(const char* const szHostCertificate, const char* const szHostKey)
{
    return dynamic_cast<SslUdpSocketImpl*>(GetImpl())->AddCertificat(szHostCertificate, szHostKey);
}

bool SslUdpSocket::CreateServerSide(const char* const szIpToWhere, const uint16_t sPort, const char* const szIpToBind/* = nullptr*/)
{
    return dynamic_cast<SslUdpSocketImpl*>(GetImpl())->CreateServerSide(szIpToWhere, sPort, szIpToBind);
}

bool SslUdpSocket::CreateClientSide(const char* const szIpToWhere, const uint16_t sPort, const char* const szDestAddr, const char* const szIpToBind/* = nullptr*/)
{
    return dynamic_cast<SslUdpSocketImpl*>(GetImpl())->CreateClientSide(szIpToWhere, sPort, szDestAddr, szIpToBind);
}

void SslUdpSocket::Close()
{
    dynamic_cast<SslUdpSocketImpl*>(GetImpl())->Close();
}

function<void(UdpSocket*)> SslUdpSocket::BindFuncSslInitDone(function<void(UdpSocket*)> fSllInitDone)
{
    return dynamic_cast<SslUdpSocketImpl*>(GetImpl())->BindFuncSslInitDone(fSllInitDone);
}

function<void(UdpSocket*, void*)> SslUdpSocket::BindFuncSslInitDone(function<void(UdpSocket*, void*)> fSllInitDone)
{
    return dynamic_cast<SslUdpSocketImpl*>(GetImpl())->BindFuncSslInitDone(fSllInitDone);
}

#endif // WITHOUT_OPENSSL
