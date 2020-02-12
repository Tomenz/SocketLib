/* Copyright (C) 2016-2019 Thomas Hauck - All Rights Reserved.

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


BaseSocket::BaseSocket(BaseSocketImpl* pImpl) : Impl_(pImpl)
{

}
BaseSocket::~BaseSocket() = default;
//BaseSocket::BaseSocket(BaseSocket &&) noexcept = default;
//BaseSocket& BaseSocket::operator=(BaseSocket &&) noexcept = default;

void BaseSocket::SetImpl(BaseSocketImpl* pImpl)
{
    Impl_.reset(pImpl);
}

BaseSocketImpl* BaseSocket::GetImpl()
{
    return Impl_.get();
}

int BaseSocket::GetErrorNo() const  noexcept
{
    return Impl_->GetErrorNo();
}

int BaseSocket::GetErrorLoc() const  noexcept
{
    return Impl_->GetErrorLoc();
}

function<void(BaseSocket*)> BaseSocket::BindErrorFunction(function<void(BaseSocket*)> fError) noexcept
{
    return Impl_->BindErrorFunction(fError);
}

function<void(BaseSocket*)> BaseSocket::BindCloseFunction(function<void(BaseSocket*)> fCloseing) noexcept
{
    return Impl_->BindCloseFunction(fCloseing);
}

void BaseSocket::SetErrorNo(int iErrNo) noexcept
{
    return Impl_->SetErrorNo(iErrNo);
}

uint16_t BaseSocket::GetSocketPort()
{
    return Impl_->GetSocketPort();
}

int BaseSocket::EnumIpAddresses(function<int(int, const string&, int, void*)> fnCallBack, void* vpUser)
{
    return BaseSocketImpl::EnumIpAddresses(fnCallBack, vpUser);
}

void BaseSocket::SetAddrNotifyCallback(function<void(bool, const string&, int, int)>& fnCbAddrNotify)
{
    return BaseSocketImpl::SetAddrNotifyCallback(fnCbAddrNotify);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TcpSocket::TcpSocket() : BaseSocket(new TcpSocketImpl(this))
{
}

TcpSocket::TcpSocket(TcpSocketImpl* const impl) : BaseSocket(impl)
{

}

TcpSocket::~TcpSocket() = default;
//TcpSocket::TcpSocket(TcpSocket &&) noexcept = default;
//TcpSocket& TcpSocket::operator=(TcpSocket &&) noexcept = default;

bool TcpSocket::Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint/* = AF_UNSPEC*/)
{
    return reinterpret_cast<TcpSocketImpl*>(Impl_.get())->Connect(szIpToWhere, sPort, AddrHint);
}
uint32_t TcpSocket::Read(void* buf, uint32_t len)
{
    return reinterpret_cast<TcpSocketImpl*>(Impl_.get())->Read(buf, len);
}
uint32_t TcpSocket::PutBackRead(void* buf, uint32_t len)
{
    return reinterpret_cast<TcpSocketImpl*>(Impl_.get())->PutBackRead(buf, len);
}
size_t TcpSocket::Write(const void* buf, size_t len)
{
    return reinterpret_cast<TcpSocketImpl*>(Impl_.get())->Write(buf, len);
}
void TcpSocket::StartReceiving()
{
    reinterpret_cast<TcpSocketImpl*>(Impl_.get())->StartReceiving();
}
void TcpSocket::Close() noexcept
{
    reinterpret_cast<TcpSocketImpl*>(Impl_.get())->Close();
}
void TcpSocket::SelfDestroy() noexcept
{
    reinterpret_cast<TcpSocketImpl*>(Impl_.get())->SelfDestroy();
}
void TcpSocket::Delete() noexcept
{
    reinterpret_cast<TcpSocketImpl*>(Impl_.get())->Delete();
}
uint32_t TcpSocket::GetBytesAvailible() const noexcept
{
    return reinterpret_cast<TcpSocketImpl*>(Impl_.get())->GetBytesAvailible();
}
uint32_t TcpSocket::GetOutBytesInQue() const noexcept
{
    return reinterpret_cast<TcpSocketImpl*>(Impl_.get())->GetOutBytesInQue();
}

function<void(TcpSocket*)> TcpSocket::BindFuncBytesReceived(function<void(TcpSocket*)> fBytesReceived) noexcept
{
    return reinterpret_cast<TcpSocketImpl*>(Impl_.get())->BindFuncBytesReceived(fBytesReceived);
}
function<void(TcpSocket*)> TcpSocket::BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted) noexcept
{
    return reinterpret_cast<TcpSocketImpl*>(Impl_.get())->BindFuncConEstablished(fClientConneted);
}

bool TcpSocket::IsSslConnection() const noexcept 
{ 
    return false; 
}

const string& TcpSocket::GetClientAddr() const noexcept
{
    return reinterpret_cast<TcpSocketImpl*>(Impl_.get())->GetClientAddr();
}
uint16_t TcpSocket::GetClientPort() const noexcept
{
    return reinterpret_cast<TcpSocketImpl*>(Impl_.get())->GetClientPort();
}
const string& TcpSocket::GetInterfaceAddr() const noexcept
{
    return reinterpret_cast<TcpSocketImpl*>(Impl_.get())->GetInterfaceAddr();
}
uint16_t TcpSocket::GetInterfacePort() const noexcept
{
    return reinterpret_cast<TcpSocketImpl*>(Impl_.get())->GetInterfacePort();
}

const TcpServer* TcpSocket::GetServerSocketRef() const noexcept
{
    return reinterpret_cast<TcpSocketImpl*>(Impl_.get())->GetServerSocketRef();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TcpServer::TcpServer() : BaseSocket(new TcpServerImpl(this))
{
}

TcpServer::TcpServer(TcpServerImpl* const impl) : BaseSocket(impl)
{
}

TcpServer::~TcpServer() = default;
//TcpServer::TcpServer(TcpServer &&) noexcept = default;
//TcpServer& TcpServer::operator=(TcpServer &&) noexcept = default;

bool TcpServer::Start(const char* const szIpAddr, const uint16_t sPort)
{
    return reinterpret_cast<TcpServerImpl*>(Impl_.get())->Start(szIpAddr, sPort);
}
unsigned short TcpServer::GetServerPort()
{
    return reinterpret_cast<TcpServerImpl*>(Impl_.get())->GetServerPort();
}
void TcpServer::BindNewConnection(function<void(const vector<TcpSocket*>&)> fnNewConnection) noexcept
{
    reinterpret_cast<TcpServerImpl*>(Impl_.get())->BindNewConnection(fnNewConnection);
}
void TcpServer::Close() noexcept
{
    reinterpret_cast<TcpServerImpl*>(Impl_.get())->Close();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

UdpSocket::UdpSocket() : BaseSocket(new UdpSocketImpl(this))
{
}

UdpSocket::UdpSocket(UdpSocketImpl* const impl) : BaseSocket(impl)
{

}

UdpSocket::~UdpSocket() = default;
//UdpSocket::UdpSocket(UdpSocket && src) noexcept = default;
//UdpSocket& UdpSocket::operator=(UdpSocket && src) noexcept = default;

bool UdpSocket::Create(const char* const szIpToWhere, const uint16_t sPort, const char* const szIpToBind/* = nullptr*/)
{
    return reinterpret_cast<UdpSocketImpl*>(Impl_.get())->Create(szIpToWhere, sPort, szIpToBind);
}

bool UdpSocket::EnableBroadCast(bool bEnable/* = true*/)
{
    return reinterpret_cast<UdpSocketImpl*>(Impl_.get())->EnableBroadCast(bEnable);
}

bool UdpSocket::AddToMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex)
{
    return reinterpret_cast<UdpSocketImpl*>(Impl_.get())->AddToMulticastGroup(szMulticastIp, szInterfaceIp, nInterfaceIndex);
}

bool UdpSocket::RemoveFromMulticastGroup(const char* const szMulticastIp, const char* const szInterfaceIp, uint32_t nInterfaceIndex)
{
    return reinterpret_cast<UdpSocketImpl*>(Impl_.get())->RemoveFromMulticastGroup(szMulticastIp, szInterfaceIp, nInterfaceIndex);
}

uint32_t UdpSocket::Read(void* buf, uint32_t len, string& strFrom)
{
    return reinterpret_cast<UdpSocketImpl*>(Impl_.get())->Read(buf, len, strFrom);
}

size_t UdpSocket::Write(const void* buf, size_t len, const string& strTo)
{
    return reinterpret_cast<UdpSocketImpl*>(Impl_.get())->Write(buf, len, strTo);
}

void UdpSocket::Close() noexcept
{
    reinterpret_cast<UdpSocketImpl*>(Impl_.get())->Close();
}

uint32_t UdpSocket::GetBytesAvailible() const noexcept
{
    return reinterpret_cast<UdpSocketImpl*>(Impl_.get())->GetBytesAvailible();
}

uint32_t UdpSocket::GetOutBytesInQue() const noexcept
{
    return reinterpret_cast<UdpSocketImpl*>(Impl_.get())->GetBytesAvailible();
}

function<void(UdpSocket*)> UdpSocket::BindFuncBytesReceived(function<void(UdpSocket*)> fBytesReceived) noexcept
{
    return reinterpret_cast<UdpSocketImpl*>(Impl_.get())->BindFuncBytesReceived(fBytesReceived);
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
//SslTcpSocket::SslTcpSocket(SslTcpSocket &&) noexcept = default;
//SslTcpSocket& SslTcpSocket::operator=(SslTcpSocket &&) noexcept = default;

bool SslTcpSocket::AddServerCertificat(const char* szCAcertificate, const char* szHostCertificate, const char* szHostKey, const char* szDhParamFileName)
{
    return reinterpret_cast<SslTcpSocketImpl*>(Impl_.get())->AddServerCertificat(szCAcertificate, szHostCertificate, szHostKey, szDhParamFileName);
}

bool SslTcpSocket::AddCertificat(const char* const szHostCertificate, const char* const szHostKey)
{
    return reinterpret_cast<SslTcpSocketImpl*>(Impl_.get())->AddCertificat(szHostCertificate, szHostKey);
}

bool SslTcpSocket::SetCipher(const char* const szCipher)
{
    return reinterpret_cast<SslTcpSocketImpl*>(Impl_.get())->SetCipher(szCipher);
}

bool SslTcpSocket::SetAcceptState()
{
    return reinterpret_cast<SslTcpSocketImpl*>(Impl_.get())->SetAcceptState();
}

bool SslTcpSocket::Connect(const char* const szIpToWhere, const uint16_t sPort, const int AddrHint/* = AF_UNSPEC*/)
{
    return reinterpret_cast<SslTcpSocketImpl*>(Impl_.get())->Connect(szIpToWhere, sPort, AddrHint);
}

void SslTcpSocket::Close() noexcept
{
    reinterpret_cast<SslTcpSocketImpl*>(Impl_.get())->Close();
}

function<void(TcpSocket*)> SslTcpSocket::BindFuncConEstablished(function<void(TcpSocket*)> fClientConneted) noexcept
{
    return reinterpret_cast<SslTcpSocketImpl*>(Impl_.get())->BindFuncConEstablished(fClientConneted);
}

bool SslTcpSocket::IsSslConnection() const noexcept
{
    return true;
}

void SslTcpSocket::SetAlpnProtokollNames(vector<string>& vProtoList)
{
    reinterpret_cast<SslTcpSocketImpl*>(Impl_.get())->SetAlpnProtokollNames(vProtoList);
}

const string SslTcpSocket::GetSelAlpnProtocol() const
{
    return reinterpret_cast<SslTcpSocketImpl*>(Impl_.get())->GetSelAlpnProtocol();
}

void SslTcpSocket::SetTrustedRootCertificates(const char* const szTrustRootCert)
{
    reinterpret_cast<SslTcpSocketImpl*>(Impl_.get())->SetTrustedRootCertificates(szTrustRootCert);
}

long SslTcpSocket::CheckServerCertificate(const char* const szHostName)
{
    return reinterpret_cast<SslTcpSocketImpl*>(Impl_.get())->CheckServerCertificate(szHostName);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

SslTcpServer::SslTcpServer() : TcpServer(new SslTcpServerImpl(this))
{
}

SslTcpServer::~SslTcpServer() = default;

bool SslTcpServer::AddCertificat(const char* const szCAcertificate, const char* const szHostCertificate, const char* const szHostKey)
{
    return reinterpret_cast<SslTcpServerImpl*>(Impl_.get())->AddCertificat(szCAcertificate, szHostCertificate, szHostKey);
}

bool SslTcpServer::SetDHParameter(const char* const szDhParamFileName)
{
    return reinterpret_cast<SslTcpServerImpl*>(Impl_.get())->SetDHParameter(szDhParamFileName);
}

bool SslTcpServer::SetCipher(const char* const szCipher)
{
    return reinterpret_cast<SslTcpServerImpl*>(Impl_.get())->SetCipher(szCipher);
}

void SslTcpServer::SetAlpnProtokollNames(vector<string>& vProtoList)
{
    reinterpret_cast<SslTcpServerImpl*>(Impl_.get())->SetAlpnProtokollNames(vProtoList);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

SslUdpSocket::SslUdpSocket() : UdpSocket(new SslUdpSocketImpl(this))
{
}

bool SslUdpSocket::AddCertificat(const char* const szHostCertificate, const char* const szHostKey)
{
    return reinterpret_cast<SslUdpSocketImpl*>(Impl_.get())->AddCertificat(szHostCertificate, szHostKey);
}

bool SslUdpSocket::CreateServerSide(const char* const szIpToWhere, const uint16_t sPort, const char* const szIpToBind/* = nullptr*/)
{
    return reinterpret_cast<SslUdpSocketImpl*>(Impl_.get())->CreateServerSide(szIpToWhere, sPort, szIpToBind);
}

bool SslUdpSocket::CreateClientSide(const char* const szIpToWhere, const uint16_t sPort, const char* const szDestAddr, const char* const szIpToBind/* = nullptr*/)
{
    return reinterpret_cast<SslUdpSocketImpl*>(Impl_.get())->CreateClientSide(szIpToWhere, sPort, szDestAddr, szIpToBind);
}

void SslUdpSocket::Close() noexcept
{
    reinterpret_cast<SslUdpSocketImpl*>(Impl_.get())->Close();
}

function<void(UdpSocket*)> SslUdpSocket::BindFuncSslInitDone(function<void(UdpSocket*)> fSllInitDone) noexcept
{
    return reinterpret_cast<SslUdpSocketImpl*>(Impl_.get())->BindFuncSslInitDone(fSllInitDone);
}

#endif // WITHOUT_OPENSSL
