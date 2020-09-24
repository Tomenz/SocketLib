cmake_minimum_required(VERSION 3.10)

project(socketlib)

ADD_DEFINITIONS(-DUNICODE)
ADD_DEFINITIONS(-D_UNICODE)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Options
option(UA_ENABLE_ENCRYPTION_OPENSSL "Enable encryption support (uses openssl)" ON)

if(UA_ENABLE_ENCRYPTION_OPENSSL)
    find_path(OPENSSL_INCLUDE_DIR openssl/ssl.h HINTS ${OPENSSL_INCLUDE_DIR})
    find_path(OPENSSL_LIB_DIR libssl.lib HINTS ${OPENSSL_LIB_DIR})
    include_directories(${OPENSSL_INCLUDE_DIR})
else()
    ADD_DEFINITIONS(-DWITHOUT_OPENSSL)
endif()


set(targetSrc
        ${CMAKE_CURRENT_LIST_DIR}/OpenSSLWraper.cpp
        ${CMAKE_CURRENT_LIST_DIR}/SocketLip.cpp
        ${CMAKE_CURRENT_LIST_DIR}/SslSocket.cpp
        ${CMAKE_CURRENT_LIST_DIR}/StdSocket.cpp
)

add_library(socketlib STATIC ${targetSrc})

install(TARGETS socketlib DESTINATION lib)
install(FILES SocketLib.h DESTINATION include)
