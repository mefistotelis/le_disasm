# le_disasm

## Overview

libopcodes-based linear executable (MZ/LE/LX DOS EXEs) disassembler.

Provide it with LE/LX file (may have MZ stub real-mode header at start),
and it will dump compilable assembly for the whole code and data area.

Outputs AT&amp;T syntax by default (switch can be made in code).

This is a continuation of work on
[Syndicate Wars Disassembler 1.0 by Vexillium group](http://swars.vexillium.org/files/swdisasm-1.0.tar.bz2).
It took a different approach to coding than [the fork by Klei1984](https://github.com/klei1984/le_disasm),
and sources diverged very early on. If you're searching for a best solution for your case,
you may want to check both forks.

## Usage

Example use on _Syndicate Wars final EU/US release_:

```
./le_disasm -e MAIN.EXE > output.sx

```

Example use with verification and redirection of log messages to a file, on _Fatal Race beta version_:

```
./le_disasm -e FATAL.EXE > output.sx 2> stderr.txt && gcc output.sx

```

## Dependencies

- binutils-dev package

## Building

The tool should build correctly on any platform with a working port of `libopcodes`.
Though the `libopcodes` and `libbfd` APIs are considered internal between loader and gdb,
and therefore are not exactly stable. If using newer versions of the libs, it may
be required to do some code alterations.

Below there are tested ways of building.

### General building instructions

To build **LE Disassembler**, you will need the following:

* GNU Autotools
* GNU C++ compiler
* libOpcodes (part of GNU Binutils) dev package

Once you've made sure you have the above, proceed with the following steps:

1. go into the directory with `le_disasm` source release (containing `src` `res` etc.)
2. do `autoreconf -if` to create build scripts from templates
3. do `./configure` to make the build scripts find required toolchain and libraries
4. do `make` to compile the executable file

You should now have a working `src/le_disasm` executable file.

#### Build example - Ubuntu 22.04 64-bit

Here are specific commands required to compile the executable on Ubuntu linux.

First install the dependencies:

```
sudo apt install libc6-dev gettext
sudo apt install libiberty-dev
sudo apt install binutils-dev
sudo apt install libzstd-dev
sudo apt install build-essential autoconf libtool make
```

Now as our host is ready, we can start working on the actual `le_disasm` sources.
Go to that folder, and generate build scripts from templates using autotools:

```
autoreconf -ivf
```

Next, proceed with the build steps; we will do that in a separate folder.

```
mkdir -p release; cd release
../configure
make V=1
```

The `V=1` variable makes `make` print each command it executes, which makes
diagnosing issues easier.

On success, this will create `release/src/le_disasm` executable file.

In case you want a debug version of the binary (required for tracing bugs within the
tool), the commands should include optimizations disable and debug symbols enable.
To get such build, go to the `le_disasm` folder; then it would be prudent to create
a separate build directory for debug version, and compile the tool there:

```
mkdir -p debug; cd debug
CPPFLAGS="-DDEBUG -D__DEBUG" CFLAGS="-g -O0 -Wall" CXXFLAGS="-g -O0 -Wall" LDFLAGS="-g -O0 -Wall" ../configure
make V=1
```

On success, this will create `debug/src/le_disasm` executable file.

Explanation of the parameters:

* The `-g -O0` flags make it easier to use a debugger like _GDB_ with the
  binary, by storing symbols and disabling code optimizations.
* The `-Wall` flags enable displaying more warnings during compilation.
* The `-DDEBUG -D__DEBUG` defines make the binary print more information.
* The flags are set separately for C preprocessor (`CPP`), compilers (`C`, `CXX`)
  and linker (`LD`). See [GNU Automake documentation](https://www.gnu.org/software/automake/manual/html_node/Programs.html)
  for details on that.

#### Build example - MSYS2 updated 2023-07 on Windows

Using Minimal System and the MinGW toolchain available within, it is possible
to build the executable using the same way as for UNIX systems, with bash and autotools.

First install the dependencies - mingw64:

```
pacman -S mingw-w64-x86_64-binutils mingw-w64-x86_64-pkgconf mingw-w64-x86_64-make mingw-w64-x86_64-gcc
```

Now as our host is ready, we can start working on the actual `le_disasm` sources.
We will provide path to mingw64 aclocal config, just in case another toolchain is default.
Go to the `le_disasm` folder, and generate build scripts from templates using autotools:

```
autoreconf -ivf --include=/mingw64/share/aclocal/
```

Next, proceed with the build steps; we will do that in a separate folder.
Note how we are modifying PATH environment variable to make shell search for mingw32
binaries before the default mingw64:

```
mkdir -p release; cd release
../configure
make V=1
```

On success, this will create `release/src/le_disasm.exe` executable file.
Note that you need a pack of DLL files from `mingw64` folder to corretly run
the executable on other Windows installations.

In case you want a debug version of the binary (required for tracing bugs within the
tool), the commands should include optimizations disable and debug symbols enable.
To get such build, go to the `le_disasm` folder; then it would be prudent to create
a separate build directory for debug version, and compile the tool there:

```
mkdir -p debug; cd debug
CPPFLAGS="-DDEBUG" CFLAGS="-g -O0" CXXFLAGS="-g -O0" LDFLAGS="-g -O0" ../configure
make V=1
```
On success, this will create `debug/src/le_disasm.exe` executable file.

#### Build example - 32-bit toolchain of MSYS2 updated 2023-07 on Windows

Using Minimal System and the MinGW toolchain available within, it is possible
to build the executable using the same way as for UNIX systems, with bash and autotools.

First install the dependencies - mingw32, since we aim for 32-bit build:

```
pacman -S mingw-w64-i686-binutils mingw-w64-i686-pkgconf mingw-w64-i686-make mingw-w64-i686-gcc
```

Now as our host is ready, we can start working on the actual `le_disasm` sources.
We will still have to provide paths to 32-bit configuration - MSYS will prefer
folders with data for 64-bit building.
Go to the `le_disasm` folder, and generate build scripts from templates using autotools:

```
autoreconf -ivf --include=/mingw32/share/aclocal/
```

Next, proceed with the build steps; we will do that in a separate folder.
Note how we are modifying PATH environment variable to make shell search for mingw32
binaries before the default mingw64:

```
mkdir -p release; cd release
PATH="/mingw32/bin:$PATH" CFLAGS="-m32" CXXFLAGS="-m32" LDFLAGS="-m32" ../configure
PATH="/mingw32/bin:$PATH" make V=1
```

On success, this will create `release/src/le_disasm.exe` executable file.
Note that you need a pack of 32-bit DLL files from `mingw32` folder to corretly run
the 32-bit executable on 64-bit Windows.

In case you want a debug version of the binary (required for tracing bugs within the
tool), the commands should include optimizations disable and debug symbols enable.
To get such build, go to the `le_disasm` folder; then it would be prudent to create
a separate build directory for debug version, and compile the tool there:

```
mkdir -p debug; cd debug
PATH="/mingw32/bin:$PATH" CPPFLAGS="-DDEBUG" CFLAGS="-m32 -g -O0" CXXFLAGS="-m32 -g -O0" LDFLAGS="-m32 -g -O0" ../configure
PATH="/mingw32/bin:$PATH" make V=1
```
On success, this will create `debug/src/le_disasm.exe` executable file.

## Done

That's all. Have fun using the tool!
