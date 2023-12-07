# dotnet6-stage0

This is the .NET 6.0 package for Alpine Linux.

Please report any issues [using Gitlab](https://gitlab.alpinelinux.org/alpine/aports/-/issues/new) and tag @ayakael

# Building info

## Generated packages
* `dotnet6` (empty package to go around `buildrepo` build ordering bug)
* `dotnet6-stage0-bootstrap` (packages binary bootstrap artifacts)
* `dotnet6-stage0-artifacts` (packages non-binary bootstrap artifacts)

## How to build dotnet6 on Alpine
As dotnet is a self-hosting compiler (thus it compiles using itself), it
requires a bootstrap for the initial build. To solve this problem, this package
follows the `stage0` proposal outlined [here](https://lists.alpinelinux.org/~alpine/devel/%3C33KG0XO61I4IL.2Z7RTAZ5J3SY6%408pit.net%3E)

The goal of `stage0` is to bootstrap dotnet with as little intervention as
possible, thus allowing seamless Alpine upgrades. Unfortunately, upstream only
builds bootstraps for Alpine on `x86_64`, `aarch64`, and `armv7`. Thus, `stage0`
has also been designed to be crossbuild aware, allowing bootstrapping to other
platforms.

In summary, dotnet6 is built using three different aports.

* `community/dotnet6-stage0`
Builds minimum components for full build of dotnet6, and packages these in an initial 
`dotnet6-stage0-bootstrap` package that `dotnet7-build` pulls.
* `community/dotnet6-build`
Builds full and packages dotnet6 fully using either stage0 or previoulsy built
dotnet6 build.
* `community/dotnet6-runtime`
As abuild does not allow different versions for subpackages, a different aport
is required to package runtime bits from dotnet6-build.

## Crossbuilding with `stage0`
Crossbuilding `stage0` is a three step process:
1. Build sysroot for target platform by using `scripts/bootstrap.sh` in aports repo:
```
./bootstrap.sh $CTARGET_ARCH
```
2. Although not necessary, it is recommended to add Alpine repositories to
   `$HOME/sysroot-$CTARGET_ARCH/etc/apk/repositories`, making sure to add required
   keys. This makes it so that whatever package is not built in step 1 will
   be pulled from package repos
3. Crossbuild `dotnet6-stage0` via:
```
CHOST=$CTARGET_ARCH abuild -r
```

# Specification

This package follows [package naming and contents suggested by upstream](https://docs.microsoft.com/en-us/dotnet/core/build/distribution-packaging),
with two exceptions. It installs dotnet to `/usr/lib/dotnet` (aka `$_libdir`). 
In addition, the package is named `dotnet6` as opposed to `dotnet-6.0`
to match Alpine Linux naming conventions for packages with many installable versions

# Contributing

The steps below are for the final package. Please only contribute to a
pre-release version if you know what you are doing. Original instructions
follow.

## General Changes

1. Fork the main aports repo.

2. Checkout the forked repository.

    - `git clone ssh://git@gitlab.alpinelinux.org/$USER/aports`
    - `cd community/dotnet6-stage0`

3. Make your changes. Don't forget to add a changelog.

4. Do local builds.

    - `abuild -r`

5. Fix any errors that come up and rebuild until it works locally.

6. Commit the changes to the git repo in a git branch

    - `git checkout -b dotnet6/<name>`
    - `git add` any new patches
    - `git remove` any now-unnecessary patches
    - `git commit -m 'community/dotnet6-stage0: descriptive description'`
    - `git push`

7. Create a merge request with your changes, tagging @ayakael for review.

8. Once the tests in the pull-request pass, and reviewers are happy, your changes
   will be merged.

## Updating to an new upstream release

1. Fork the main aports repo.

2. Checkout the forked repository.

    - `git clone ssh://git@gitlab.alpinelinux.org/$USER/aports`
    - `cd community/dotnet6-stage0`


3. Build the new upstream source tarball. Update the versions in the
   APKBUILD file, and then create a snapshot. After build, update checksum.

    - `abuild snapshot`
    - `abuild checksum`

4. Do local builds.

    - `abuild -r`

5. Fix any errors that come up and rebuild until it works locally. Any
   patches that are needed at this point should be added to the APKBUILD file
   in `_patches` variable.

6. Upload the source archive to a remote location, and update `source` variable.

7. Commit the changes to the git repo in a git branch.

    - `git checkout -b dotnet6/<name>`	
    - `git add` any new patches
    - `git remove` any now-unnecessary patches
    - `git commit -m 'community/dotnet6-stage0: upgrade to <new-version>`
    - `git push`

8. Create a merge request with your changes, tagging @ayakael for review.

9. Once the tests in the pull-request pass, and reviewers are happy, your changes
   will be merged.

# Testing

This package uses CI tests as defined in `check()` function. Creating a
merge-request or running a build will fire off tests and flag any issues.

The tests themselves are contained in this external repository:
https://github.com/redhat-developer/dotnet-regular-tests/
