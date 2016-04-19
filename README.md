# OP-TEE Client API
The optee-client git, containing the source code for the TEE client library in
Linux. This component provides the TEE Client API as defined by the
GlobalPlatform TEE standard. It is distributed under the BSD 2-clause
open-source license. For a general overview of OP-TEE, please see the
[Notice.md](Notice.md) file.

In this git there are two main target/binaries to build. There is libteec.so,
which is the library that contains that API for communication with the Trusted
OS. Then the other target is the binary tee-supplicant which is a daemon serving
the Trusted OS in secure world with miscellaneous features, such as file system
access.

## License
The software is provided under the
[BSD 2-Clause](http://opensource.org/licenses/BSD-2-Clause) license.

## Platforms supported
This software in this git doesn't directly have any dependencies to any
particular hardware, since it's pure software library directly communicating
with the Linux kernel. Currently the software has been tested using:

- STMicroelectronics b2020-h416 (orly-2) hardware (32-bits)
- Some initial testing has been done using
[Foundation FVP](http://www.arm.com/fvp), which can be downloaded free of
charge.

## Get and build the software
### Get the compiler
We will strive to use the latest available compiler from Linaro. This
[file](https://github.com/OP-TEE/build/blob/master/toolchain.mk) refers to a
list of toolchains we have used and know are working in our setups. Start by
downloading and unpacking a compiler from it. Then export the PATH to the bin
folder.

	$ cd $HOME
	$ mkdir toolchains
	$ cd toolchains
	$ wget [url/to/gcc_tarball]
	$ tar xvf [gcc_tarball]
	$ export PATH=$HOME/toolchains/[gcc_extracted_dir]/bin:$PATH

### Download the source code
	$ cd $HOME
	$ mkdir devel
	$ cd devel
	$ git clone https://github.com/OP-TEE/optee_client.git

### Build
During a transition period it will be possible to build using the plain old
makefiles, but it will also be possible to build using CMake. To build using
the old makefiles, simply run:
```bash
$ cd $HOME/devel/optee_client
$ make
```

If you prefer using CMake instead, then create a build folder where you run
cmake, like this for example:
```bash
$ cd $HOME/devel/optee_client
$ make build
$ cd build

# This example uses an Armv7-A / 32bit toolchain, adjust accordingly.
$ export CC="<your_project_path>/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc"

# cmake here take optional flags, if you for example wants to install files in
# another location than default, then one can use
# -DCMAKE_INSTALL_PREFIX=<my-install-path> as an argument to cmake.
$ cmake ..
$ make

# Optional
$ make install
```

For a 64-bit build:

	$ make CROSS_COMPILE=aarch64-linux-gnu-

#### Compiler flags
To be able to see the full command when building you could build using following
flag:

`$ make V=1`

## Coding standards
In this project we are trying to adhere to the same coding convention as used in
the Linux kernel (see
[CodingStyle](https://www.kernel.org/doc/Documentation/CodingStyle)). We achieve this by running
[checkpatch](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/scripts/checkpatch.pl) from Linux kernel.
However there are a few exceptions that we had to make since the code also
follows GlobalPlatform standards. The exceptions are as follows:

- CamelCase for GlobalPlatform types are allowed.
- And we also exclude checking third party code that we might use in this
  project, such as LibTomCrypt, MPA, newlib (not in this particular git, but
  those are also part of the complete TEE solution). The reason for excluding
  and not fixing third party code is because we would probably deviate too much
  from upstream and therefore it would be hard to rebase against those projects
  later on (and we don't expect that it is easy to convince other software
  projects to change coding style).

### checkpatch
Since checkpatch is licensed under the terms of GNU GPL License Version 2, we
cannot include this script directly into this project. Therefore we have
written the Makefile so you need to explicitly point to the script by exporting
an environment variable, namely CHECKPATCH. So, suppose that the source code for
the Linux kernel is at `$HOME/devel/linux`, then you have to export like follows:

	$ export CHECKPATCH=$HOME/devel/linux/scripts/checkpatch.pl
thereafter it should be possible to use one of the different checkpatch targets
in the [Makefile](Makefile). There are targets for checking all files, checking
against latest commit, against a certain base-commit etc. For the details, read
the [Makefile](Makefile).
