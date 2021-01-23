FROM debian:buster-slim as bpftool-build
ARG KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
ARG KERNEL_REF=master
RUN apt-get update && \
  apt-get upgrade -y && \
  apt-get install -y --no-install-recommends \
  gpg gpg-agent libelf-dev libmnl-dev libc-dev iptables libgcc-8-dev \
  bash-completion binutils binutils-dev ca-certificates make git curl \
  xz-utils gcc pkg-config bison flex build-essential python3 && \
  apt-get purge --auto-remove && \
  apt-get clean

WORKDIR /tmp

RUN \
  git clone --depth 1 -b $KERNEL_REF $KERNEL_REPO && \
  cd linux/tools/bpf/bpftool/ && \
  sed -i '/CFLAGS += -O2/a CFLAGS += -static' Makefile && \
  sed -i 's/LIBS = -lelf $(LIBBPF)/LIBS = -lelf -lz $(LIBBPF)/g' Makefile && \
  printf 'feature-libbfd=0\nfeature-zlib=1\nfeature-libelf=1\nfeature-bpf=1\nfeature-libelf-mmap=1' >> FEATURES_DUMP.bpftool && \
  FEATURES_DUMP=`pwd`/FEATURES_DUMP.bpftool make -j `getconf _NPROCESSORS_ONLN` && \
  strip bpftool && \
  ldd bpftool 2>&1 | grep -q -e "Not a valid dynamic program" \
  -e "not a dynamic executable" || \
  ( echo "Error: bpftool is not statically linked"; false ) && \
  mv bpftool /usr/bin && rm -rf /tmp/linux

FROM andrewstucki/llvm10rc3-musl-toolchain

COPY --from=bpftool-build /usr/bin/bpftool /usr/bin/bpftool

ADD patches /patches/
RUN ln -s /usr/bin/clang /usr/bin/cc && \
  \
  apk add --no-cache \
  elfutils-dev \
  zlib-static \
  linux-headers \
  bcc-static \
  bcc-dev \
  patch \
  curl && \
  \
  mkdir -p /src/libbpf && cd /src/libbpf && \
  curl -L "https://github.com/libbpf/libbpf/archive/v0.3.tar.gz" \
  | tar --extract -xz --strip-components=1 && \
  \
  patch -p1 < /patches/makefile.patch && \
  patch -p1 < /patches/types.patch && \
  \
  cd src && BUILD_STATIC_ONLY=y make install && \
  \
  printf "prefix=/usr\nlibdir=/usr/lib\nincludedir=${prefix}/include\n\nName: libelf\nDescription: ELF library\nVersion: 0.168-r3\nLibs: -L${libdir} -lelf\nCflags: -I${includedir}" > /usr/lib/pkgconfig/libelf.pc

WORKDIR /src
