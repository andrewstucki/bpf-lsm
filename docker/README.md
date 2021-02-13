# Docker toolchain

This directory contains the docker configuration for the main toolchain image used in compiling this project. Included alongside the Dockerfiles are LLVM and libbpf patches to get them to build against musl. Many of them were copied/modified from the latest Alpine clang package configurations I could find when I initially built this.

Because building LLVM can be _painfully_ slow, the main tip to speed it up is to provision a 96-core latest Ubuntu box on AWS and run the `docker build` commands on it. This will likely cut down the build time for these images from a few hours to ~10 minutes. Once you're done, push the images to a docker hub repo and decommission the EC2 instance.
