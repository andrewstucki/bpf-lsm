# Example BPF LSM

This repo contains scripts and an example program to play around with BPF CO-RE modules and an LSM.

In order to be completely portable (assuming a new enough kernel), and to show how this would interop with a Rust program, the userspace components are written in a combination of Rust and C compiled with clang and linked against musl. The result should be that you can drop the output binary on any Linux 5.11+ kernel (this leverages the BPF LSM, ringbuffers, and sleepable BPF hooks) and have it run.

## Quickstart

```bash
vagrant up
make
```

In one VM ssh session:

```bash
sudo /vagrant/probe -f 1000
```

In another VM ssh session you should see something like the following happen:

```bash
vagrant@ubuntu-hirsute:~$ ls
-bash: /usr/bin/ls: Operation not permitted
```

In the first terminal you should see a log entry like:

```bash
{"@timestamp": "1612311321", "event": {"id": "943ec63d-ba17-4d4d-9a02-b61b9e103e2c", "kind": "event", "category": "process", "action": "execution-denied", "type": "start", "module": "bpf-lsm", "provider": "bprm-check-security", "sequence": "0"}, "host": {"hostname": "ubuntu-hirsute", "ip": ["10.0.2.15", "fe80::45:b3ff:fe9e:e735"], "mac": ["02:45:b3:9e:e7:35"], "uptime": "51", "os": {"type": "linux", "name": "Ubuntu", "kernel": "5.11.0-rc6-bpf-lsm"}}, "process": {"pid": 1608, "entity_id": "438a54f19a1430d9a6ce79433c3af8dc5bf0ab6e4427c872da54befc2d205628", "name": "ls", "ppid": 1492, "executable": "/usr/bin/ls", "args_count": "2", "start": "1612311321", "thread.id": "1608", "parent": {"pid": 1492, "entity_id": "da3de02e9f2a9faf7387db10ee9fa3952b8406fa37563f1351e4504f8b517ebe", "name": "bash", "ppid": 1491, "start": "1612311305", "thread.id": "1492"}}, "user": {"id": "1000", "name": "vagrant", "group": {"id": "1000", "name": "vagrant"}, "effective": {"id": "1000", "name": "vagrant", "group": {"id": "1000", "name": "vagrant"}}}}
```

## Kernel

The Vagrantfile boots a virtualbox VM with a custom Linux 5.11-rc6 build with BPF LSM kernel options
all enabled, a rust toolchain installed, and lldb for debugging builds with `rust-lldb`.

## Toolchains

The toolchain for this are all in Docker containers. The containers contain a clang 10-based compiler
that targets musl and libc++ in order to statically compile everything. As a result, you can't use any
Rust code that leverages `proc_macro` as this requires dynamically linking against glibc and gcc.
