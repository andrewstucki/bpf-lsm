# Example BPF LSM

This repo contains scripts and an example program to play around with BPF CO-RE modules and an LSM.

In order to be completely portable (assuming a new enough kernel), and to show how this would interop with a Rust program, the userspace components are written in a combination of Rust and C compiled with clang and linked against musl. The result should be that you can drop the output binary on any Linux 5.8+ kernel (for ringbuffer and LSM hook support) and have it run.

It also has some ideas around sharing userspace data via tracepoints with lsm hooks.

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
{"@timestamp": "1612372470", "event": {"id": "c252da65-7cd2-40ef-806d-ca2526ee3053", "kind": "event", "category": "process", "action": "execution-denied", "type": "start", "module": "bpf-lsm", "provider": "bprm-check-security", "sequence": "0"}, "host": {"hostname": "ubuntu-hirsute", "ip": ["10.0.2.15", "fe80::45:b3ff:fe9e:e735"], "mac": ["02:45:b3:9e:e7:35"], "uptime": "34792", "os": {"type": "linux", "name": "Ubuntu", "kernel": "5.11.0-rc6-bpf-lsm"}}, "process": {"pid": 31912, "entity_id": "bbf4e6067b5b0dbc8c21c475f61db1e4b70db392ffce5ff7cb7d34954f76db6f", "name": "ls", "ppid": 1969, "executable": "/usr/bin/ls", "args_count": "4", "start": "1612372470", "thread.id": "31912", "command_line": "ls --color=auto -l -a", "args": ["ls", "--color=auto", "-l", "-a"], "parent": {"pid": 1969, "entity_id": "066037b97fdfeb1ceefa9628036aa1b60122e2f35dc14f15a5832fcf0ed2864e", "name": "bash", "ppid": 1968, "start": "1612338051", "thread.id": "1969"}}, "user": {"id": "1000", "name": "vagrant", "group": {"id": "1000", "name": "vagrant"}, "effective": {"id": "1000", "name": "vagrant", "group": {"id": "1000", "name": "vagrant"}}}}
```

## Kernel

The Vagrantfile boots a virtualbox VM with a custom Linux 5.11-rc6 build with BPF LSM kernel options
all enabled, a rust toolchain installed, and lldb for debugging builds with `rust-lldb`.

## Toolchains

The toolchain for this are all in Docker containers. The containers contain a clang 10-based compiler
that targets musl and libc++ in order to statically compile everything. As a result, you can't use any
Rust code that leverages `proc_macro` as this requires dynamically linking against glibc and gcc.
