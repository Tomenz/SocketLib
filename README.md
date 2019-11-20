# SocketLib
Socket library written in c++11/14 for Windows/Linux (32/64) 

- IPv4 and IPv6 support
- TCP and UDP support
- multicast support for IPv4 and IPv6
- Enum all IP's on the host
- notify if host ip comes up / changes / is removed
- TLS 1.3 if openssl 1.1.1 is used
- Multithreading, none blocking. All callback function executed in own thread

Examples: https://github.com/Tomenz/Examples-SocketLib

In die Windows Project files is the "OpenSSL_HOME" enviroment variable as Include directory configuriert. Define the envirment variable, or change the include path in the visual studio project settings.

Meanwhile a smale client / server example using the "SocketLib" library<br>
*** The "SocketLib" library in this example should by compiled with WITHOUT_OPENSSL defined, so we don't need the opensll library<br>
*** If you need SSL, you have to fix the path for the openssl headers and lib's when compiling the library

```
#include <thread>
#include <conio.h>
#include <sstream>
#include <iomanip>
#include <iostream>

#include "SocketLib.h"

using namespace std;

#ifdef _DEBUG
#ifdef _WIN64
#pragma comment(lib, "x64/Debug/socketlib64d")
#else
#pragma comment(lib, "Debug/socketlib32d")
#endif
#else
#ifdef _WIN64
#pragma comment(lib, "x64/Release/socketlib64")
#else
#pragma comment(lib, "Release/socketlib32")
#endif
#endif

void ServerThread(bool* bStop)
{
    TcpServer sock;

    sock.BindErrorFunction([&](BaseSocket*) { cout << "Server socket: socket error" << endl; });
    sock.BindCloseFunction([&](BaseSocket*) { cout << "Server socket: socket closing" << endl; });
    
    // This Callback is called if a new client connects to the server. 
    sock.BindNewConnection([&](const vector<TcpSocket*>& lstSockets)
        {
            for (auto& pSocket : lstSockets)
            {
                if (pSocket != nullptr)
                {
                    pSocket->BindFuncBytesReceived([&](TcpSocket* pTcpSocket)
                        {
                            uint32_t nAvalible = pTcpSocket->GetBytesAvailible();

                            auto spBuffer = make_unique<unsigned char[]>(nAvalible + 1);

                            uint32_t nRead = pTcpSocket->Read(spBuffer.get(), nAvalible);

                            if (nRead > 0)
                            {
                                string strRec(nRead, 0);
                                copy(spBuffer.get(), spBuffer.get() + nRead, &strRec[0]);

                                stringstream strOutput;
                                strOutput << pTcpSocket->GetClientAddr() << " - Server received: " 
                                          << nRead << " Bytes, \"" << strRec << "\"" << endl;

                                cout << strOutput.str();

                                strRec = "Server echo: " + strRec;
                                pTcpSocket->Write(&strRec[0], strRec.size());

                                pTcpSocket->Close();
                            }
                        });
                    pSocket->BindErrorFunction([&](BaseSocket*) { cout << "Server: socket error" << endl; });
                    pSocket->BindCloseFunction([&](BaseSocket* pSock) 
                        {
                            // We let the socket destroy it self
                            pSock->SelfDestroy();
                            cout << "Server: socket closing" << endl;
                        });
                    pSocket->StartReceiving();
                }
            }
        });


    bool bCreated = sock.Start("0.0.0.0", 3461);  // or "::" for IPv6

    while (*bStop == false)
    {
        this_thread::sleep_for(chrono::milliseconds(10));
    }

    // Closeing the server socket will not call the close callback
    sock.Close();
}

void ClientThread(bool* bStop)
{
    TcpSocket sock;

    sock.BindErrorFunction([&](BaseSocket*) { cout << "Client: socket error" << endl; });
    sock.BindCloseFunction([&](BaseSocket*) { cout << "Client: socket closing" << endl; });
    sock.BindFuncBytesReceived([&](TcpSocket* pTcpSocket)
        {
            uint32_t nAvalible = pTcpSocket->GetBytesAvailible();

            auto spBuffer = make_unique<unsigned char[]>(nAvalible + 1);

            uint32_t nRead = pTcpSocket->Read(spBuffer.get(), nAvalible);

            if (nRead > 0)
            {
                string strRec(nRead, 0);
                copy(spBuffer.get(), spBuffer.get() + nRead, &strRec[0]);

                stringstream strOutput;
                strOutput << pTcpSocket->GetClientAddr() << " - Client received: " 
                          << nRead << " Bytes, \"" << strRec << "\"" << endl;

                cout << strOutput.str();
            }
        });

    sock.BindFuncConEstablished([&](TcpSocket* pTcpSocket)
        {
            pTcpSocket->Write("Hallo World", 11);
        });

    bool bConnected = sock.Connect("127.0.0.1", 3461); // or "::1" for IPv6
    if (bConnected == false)
        cout << "error creating client socket" << endl;

    while (*bStop == false)
    {
        this_thread::sleep_for(chrono::milliseconds(10));
    }

    // The Close call will call the Callbackfuntion above
    // but if we leave the thread, the Instance is destroyed
    // and we crash. So we disable the Callback by setting a nullptr
    sock.BindCloseFunction(nullptr);
    sock.Close();
}

int main(int argc, const char* argv[])
{
#if defined(_WIN32) || defined(_WIN64)
    // Detect Memory Leaks
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG));
#endif

    bool bStop = false;
    thread thServer = thread(bind(ServerThread, &bStop));
    this_thread::sleep_for(chrono::milliseconds(1000));
    thread thClient = thread(bind(ClientThread, &bStop));

    _getch();

    bStop = true;

    thServer.join();
    thClient.join();

    return 0;
}
```
