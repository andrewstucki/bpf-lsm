# Example BPF LSM

This repo contains scripts and an example program to play around with BPF CO-RE modules and an LSM.

In order to be completely portable (assuming a new enough kernel), and to show how this would interop with a Rust program, the userspace components are written in a combination of Rust and C compiled with clang and linked against musl. The result should be that you can drop the output binary on any Linux 5.8+ kernel (for ringbuffer and LSM hook support) and have it run.

## Quickstart

```bash
make bootstrap-vm
make clean && make
```

In one VM ssh session:

```bash
sudo /vagrant/probe -f 1000
```

In another VM ssh session you should see something like the following happen:

```bash
[vagrant@localhost ~]\$ ls
-bash: /usr/bin/ls: Operation not permitted
```

In the first terminal you should see a log entry like:

```bash
Event { tid: 1319, pid: 1319, ppid: 1278, gid: 1000, uid: 1000, state: Denied, filename: "/usr/bin/ls", program: "bash" }
```

## VM

```bash
make bootstrap-vm
# subsequent boots you can just call "vagrant up"
```

The `Vagrantfile` in the root of the repo contains a Fedora 33 VM that can run with Virtualbox and a provisioning script that pulls down and installs a pre-built kernel with some slight modifications from the stock Fedora kernel. The main difference is overriding the `CONFIG_LSM` kconfig value to include `bpf`.

## Kernel

The scripts to rebuild the kernel are in `scripts`. Most likely you won't need to use them since I already uploaded the pre-built kernel rpms to a public yum repo. The VM provisioning process pulls down this prebuilt kernel. Be advised that if you don't build these kernels on a relatively beefy machine, that the process can take a couple of hours, the official Fedora builds build the kernel and all modules twice.

## Toolchains

The toolchain for this are all in Docker containers. The Dockerfile manifests for the various stages of containers are in the `toolchain` directory. The `build` make target is already configured to shell out to Docker for the build.
