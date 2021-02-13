FROM alpine:3.11.3

ADD patches /patches/
RUN apk add --update-cache \
  clang-dev \
  clang-static \
  cmake \
  g++ \
  git \
  libexecinfo-dev \
  linux-headers \
  make \
  ninja \
  patch \
  python \
  zlib-dev \
  curl && \
  rm -rf /var/cache/apk/* && \
  \
  mkdir -p /src/llvm && cd /src/llvm && \
  \
  curl -L "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0-rc3/llvm-10.0.0rc3.src.tar.xz" \
  | tar --extract --xz --strip-components=1 && \
  \
  mkdir -p projects/compiler-rt && \
  \
  curl -L "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0-rc3/compiler-rt-10.0.0rc3.src.tar.xz" \
  | tar --extract --xz --strip-components=1 --directory=projects/compiler-rt && \
  \
  mkdir -p projects/libcxx && \
  curl -L "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0-rc3/libcxx-10.0.0rc3.src.tar.xz" \
  | tar --extract --xz --strip-components=1 --directory=projects/libcxx && \
  \
  mkdir -p projects/libcxxabi && \
  curl -L "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0-rc3/libcxxabi-10.0.0rc3.src.tar.xz" \
  | tar --extract --xz --strip-components=1 --directory=projects/libcxxabi && \
  \
  mkdir -p projects/libunwind && \
  curl -L "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0-rc3/libunwind-10.0.0rc3.src.tar.xz" \
  | tar --extract --xz --strip-components=1 --directory=projects/libunwind && \
  \
  mkdir -p tools/clang && \
  curl -L "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0-rc3/clang-10.0.0rc3.src.tar.xz" \
  | tar --extract --xz --strip-components=1 --directory=tools/clang && \
  \
  mkdir -p tools/clang/tools/extra && \
  curl -L "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0-rc3/clang-tools-extra-10.0.0rc3.src.tar.xz" \
  | tar --extract --xz --strip-components=1 --directory=tools/clang/tools/extra && \
  \
  mkdir -p tools/lld && \
  curl -L "https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0-rc3/lld-10.0.0rc3.src.tar.xz" \
  | tar --extract --xz --strip-components=1 --directory=tools/lld && \
  \
  patch -p1 < /patches/LLVMConfig.patch && \
  patch -p1 < /patches/strtoll.patch && \
  \
  mkdir -p build && cd build && \
  cmake .. \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DLIBCXXABI_LIBCXX_PATH=/src/llvm/projects/libcxx \
  -DLIBCXXABI_LIBCXX_INCLUDES=/src/llvm/projects/libcxx/include \
  -DLIBCXX_ENABLE_SHARED=OFF \
  -DCLANG_DEFAULT_LINKER=lld \
  -DLLVM_ENABLE_RTTI=ON \
  -DLLVM_ENABLE_EH=ON \
  -DLLVM_ENABLE_BINDINGS=OFF \
  -DLIBCXXABI_ENABLE_STATIC_UNWINDER=ON \
  -DLIBCXXABI_USE_LLVM_UNWINDER=ON \
  -DLIBCXX_LIBCXXABI_INCLUDES_INTERNAL=/src/llvm/projects/libcxxabi/include \
  -DLIBCXX_HAS_MUSL_LIBC=ON \
  -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
  -DLIBUNWIND_ENABLE_SHARED=OFF \
  -DCLANG_DEFAULT_CXX_STDLIB=libc++ \
  -DCLANG_DEFAULT_RTLIB=compiler-rt \
  -DLLVM_DEFAULT_TARGET_TRIPLE=x86_64-pc-linux-musl \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_TARGET_ARCH=x86_64 \
  -DLLVM_TARGETS_TO_BUILD="X86;BPF" \
  -DLIBCXXABI_USE_COMPILER_RT=ON \
  -DLIBCXX_USE_COMPILER_RT=ON \
  -DCOMPILER_RT_BUILD_BUILTINS=ON \
  -DCOMPILER_RT_BUILD_SANITIZERS=OFF \
  -DCOMPILER_RT_BUILD_XRAY=OFF \
  -DCOMPILER_RT_USE_BUILTINS_LIBRARY=ON \
  -G Ninja && \
  ninja && \
  ninja install && \
  \
  apk del --purge \
  g++ \
  git \
  linux-headers \
  patch \
  python \
  curl && \ 
  \
  apk --no-cache add libc-dev && \
  \
  cd / && rm -rf /src/llvm && \
  ln -s /usr/bin/llvm-addr2line /usr/bin/addr2line && \
  ln -s /usr/bin/llvm-ar /usr/bin/ar && \
  ln -s /usr/bin/llvm-as /usr/bin/as && \
  ln -s /usr/bin/llvm-dlltool /usr/bin/dlltool && \
  ln -s /usr/bin/llvm-lipo /usr/bin/lipo && \
  ln -s /usr/bin/llvm-nm /usr/bin/nm && \
  ln -s /usr/bin/llvm-objcopy /usr/bin/objcopy && \
  ln -s /usr/bin/llvm-objdump /usr/bin/objdump && \
  ln -s /usr/bin/llvm-ranlib /usr/bin/ranlib && \
  ln -s /usr/bin/llvm-readelf /usr/bin/readelf && \
  ln -s /usr/bin/llvm-readobj /usr/bin/readobj && \
  ln -s /usr/bin/llvm-rtdyld /usr/bin/rtdyld && \
  ln -s /usr/bin/llvm-strip /usr/bin/strip
