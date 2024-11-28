
# musl-perf

This package provides a standard C Library implementation based on [musl libc][1].
In addition, it is statically linked with [glibc-string][2] library that provides
extra performance optimizations for string manipulation and memory functions.
It supports runtime CPU features detection, indirect functions that select
an appropriate implementation of the optimized ASM versions included in the
package.

# Libraries

`musl-perf` package contains the static libraries based on musl libc.
Moreover, the provided libraries are statically linked with external
`libglibc-string.a` library ([glibc-string][3] package) to provide seamless
build and runtime integration with this package (including sub-packages).

In addition, `musl-perf-dev` sub-package provides a separate static library
`libc-noglibc-string.a` without the external library: `libglibc-string.a`.

# License

The package is distributed under the MIT license.

`libglibc-string.a` library that is linked with these package's libraries
and provided by the standalone [glibc-string][3] package, distributed under
LGPL-2.1-or-later license.

When installing `musl-perf-dev` package, [glibc-string][3] package is also
installed as a dependency package, which provides `libglibc-string.a` library.

# External sources

The source code of `libglibc-string.a` library is available [here][2], and
the source code of `glibc-string` package itself is available [here][3].


[1]: https://musl.libc.org/
[2]: https://github.com/bell-sw/glibc-string/
[3]: https://github.com/bell-sw/alpaquita-aports/tree/stream/core/glibc-string/
