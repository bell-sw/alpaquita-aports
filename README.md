# Alpaquita Linux aports repository

This repository contains APKBUILD files, patches and scripts for all Alpaquita Linux packages.

Each git branch contains files for the corresponding Alpaquita Linux release.

## Usage

Building of packages is supported only in the Alpaquita Linux environment.

In order to build a package navigate to the directory containing its APKBUILD file and start
the build process with the `abuild` tool:

```
cd core/glibc
abuild -r
```

## More information

For documentation and support information, refer to [the official page](https://bell-sw.com/alpaquita-linux/).

