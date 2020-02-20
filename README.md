# Introduction

This project is a free and opensource implementation of SecureDeviceGrid
(http://securedevicegrid.com/) communication protocol. The intention of this
effort is to enable independent non-commercial software, like OpenHAB
(http://openhab.org), to integrate products, made by Danfoss company (and
possibly some others, whose vendors chose to use the SecureDeviceGrid as their
communication platform), offering no other means of connectivity, except using
the cloud. Currently known such products include:

1. DEVIReg(tm) Smart floor heating thermostat (https://www.devismart.com/)
2. Danfoss Living Connect(tm) (http://www.smartheating.danfoss.com/)

This product is being developed using reverse engineering techniques. I, Pavel
Fedin, started this project on my own behalf in my own private time; and have
no affitiations with either Trifork or Danfoss companies, other than owning
a DEVIReg(tm) Smart product. My contact email is pavel_fedin@mail.ru.

# Legal notice

The code of opensdg library is licensed under GPL v3. However, since the
SecureDeviceGrid is a proprietary communication platform, it is strictly
forbidden and illegal to use this code in any other way, like hosting own
services on the cloud, perform security attacks on legitimate users of the
cloud, or infringe on commercial interests of the respective owner of the cloud
infrastructure, the Trifork company, in any way. Any commercial use of this code
is also strictly prohibited. If you are seeking to build and sell your own
product, using the SecureDeviceGrid technology, please contact its owners, the
Trifork company.

# Building instructions

## Prerequisites:

- protobuf (https://github.com/protocolbuffers/protobuf)
- protobuf-c (https://github.com/protobuf-c/protobuf-c)
- libsodium (https://download.libsodium.org)
- Java DK (optional, needed for building Java binding)

## Building on UNIX

UNIX build process is very straightforward. Download and install your dependencies using
package management facilities of your distribution, then configure the build using cmake
as usual. All the dependencies should be discovered automatically.

## Building on Windows

Windows build has been verified using Visual Studio IDE. These instructions assume you
are using Visual Studio 2019 on x86-64 architecture and the latest cmake. For different
versions or different compilers you might need to supply appropriate -G argument for cmake.

In order to simplify managing dependencies on Windows it's strongly recommended
to build static version of the library.

Unfortunately protobuf and protobuf-c are not distributed in binary format for
Windows, so it will be necessary to build these prerequisites from source code.

Note that for INSTALL target to work the Visual Studio should run with elevated
Administrator privileges.

1. Build and install protobuf library and compiler

- cd D:/path/to/protobuf
- mkdir .build-win64
- cd .build-win64
- cmake ..\cmake -DCMAKE_INSTALL_PREFIX="C:\Program Files\protobuf" -Thost=x64
- Open resulting protobuf.sln
- Select "Release" configuration and execute BUILD_ALL and INSTALL targets.
- Add environment variable: Protobuf_DIR=C:\Program Files\protobuf
- Add C:\Program Files\protobuf\bin to your %PATH%
  
2. Build and install protobuf-c

   protobuf-c by default wants to build dll flavor, so we need to switch to static build
explicitly.

- cd D:/path/to/protobuf-c
- mkdir .build-win64
- cd .build-win64
- cmake ..\build-cmake -DCMAKE_INSTALL_PREFIX="C:\Program Files\protobuf-c" -DMSVC_STATIC_BUILD=ON -Thost=x64
- Open resulting protobuf-c.sln
- Select "Release" configuration and execute BUILD_ALL and INSTALL targets.
- Add C:\Program Files\protobuf-c\bin to your %PATH%

3. Install libsodium binary distribution

Simply download and unpack somewhere the latest binary distribution. You will need to supply SODIUM_ROOT
variable to cmake when configuring OpenSDG.

4. Build the opensdg library

- cd D:/path/to/opensdg
- mkdir .build-win64
- cd .build-win64
- cmake .. -DSODIUM_ROOT=D:\path\to\libsodium
- Open resulting protobuf-c.sln
- Select "Release" configuration and execute BUILD_ALL and INSTALL targets.
