
#include <memory>
#include <mutex>
#include "OpenSSLWraper.h"

using namespace std;

// Initialize the OpenSSL Library
unique_ptr<mutex[]> OpenSSLWrapper::InitOpenSSL::m_pmutLocks;
