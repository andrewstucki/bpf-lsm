# VM generation

This directory contains the kernel config for the Virtualbox image referenced in the Vagrantfile. Additionally, it has a packer configuration for generating a new Vagrant Cloud-hosted Vagrant box.

For now, rebuilding the kernel deb and the Vagrant image is a fairly manual. Some tips to speed it up:

1. Provision a 96-core latest Ubuntu box on AWS.
2. Most of the instructions and dependencies for building a debian kernel package can be found [here](https://wiki.ubuntu.com/KernelTeam/GitKernelBuild).
3. Copy/upload the kernel config file in this directory.
4. You'll likely need a newer version of `pahole` than ships with whatever Ubuntu version comes in the EC2 box in order to handle the latest BPF/BTF changes. You can manually download/install the debian packages from [launchpad](https://launchpad.net/ubuntu/+source/dwarves-dfsg).
5. Once the kernel is done building, upload the package artifacts some place that can be pulled down on the public internet. Decommission the VM to avoid $$$. Run packer.
