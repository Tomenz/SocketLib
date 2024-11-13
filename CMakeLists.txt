cmake_minimum_required(VERSION 3.10)

project(socketlib)

ADD_DEFINITIONS(-DUNICODE)
ADD_DEFINITIONS(-D_UNICODE)

# specify the C++ standard
set(SUPPORTED_CXX_STANDARDS 14 17)
if(NOT DEFINED CMAKE_CXX_STANDARD)
  message(STATUS "Setting C++ version to '14' as none was specified.")
  set(CMAKE_CXX_STANDARD 14)
  if (WIN32)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NDEBUG _CONSOLE _SCL_SECURE_NO_WARNINGS NOGDICAPMASKS NOVIRTUALKEYCODES NOWINMESSAGES NOWINSTYLES NOSYSMETRICS NOMENUS NOICONS NOKEYSTATES NOSYSCOMMANDS NORASTEROPS NOSHOWWINDOW OEMRESOURCE NOATOM NOCLIPBOARD NOCOLOR NOCTLMGR NODRAWTEXT NOGDI NOKERNEL NOUSER NONLS NOMB NOMEMMGR NOMETAFILE NOMINMAX NOMSG NOOPENFILE NOSCROLL NOSOUND NOTEXTMETRIC NOWH NOWINOFFSETS NOCOMM NOKANJI NOHELP NOPROFILER NODEFERWINDOWPOS NOMCX)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
    add_compile_options("/EHa")
  else()
    string(FIND "${CMAKE_CXX_FLAGS_DEBUG}" "-O0" nPos)
    if(${nPos} EQUAL "-1")
      SET(CMAKE_CXX_FLAGS_DEBUG "-O0 -g3 -ggdb -D_DEBUG -DDEBUG")
      add_compile_options("-Wall" "-Wpedantic" "-Wextra" "-fexceptions")
    else()
      message(STATUS "${PROJECT_NAME}: CMAKE_CXX_FLAGS_DEBUG hat bereits -O0 enthalten")
    endif()
  endif()
else()
  message(STATUS "${PROJECT_NAME}: CMAKE_CXX_STANDARD=${CMAKE_CXX_STANDARD} set by parent project.")
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
