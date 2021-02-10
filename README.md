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
vagrant@ubuntu-hirsute:~$ sudo /vagrant/probe -b 1 -f \
'reject bprm_check_security when user.id == 1000 and process.executable == "/usr/bin/ls"'
```

In another VM ssh session you should see something like the following happen:

```bash
vagrant@ubuntu-hirsute:~$ ls
-bash: /usr/bin/ls: Operation not permitted
```

In the first terminal you should see a log entry like:

```bash
vagrant@ubuntu-hirsute:~$ sudo /vagrant/probe -b 1 -f \
'reject bprm_check_security when user.id == 1000 and process.executable == "/usr/bin/ls"'
{"@timestamp": "1612972701", "event": {"id": "d920dd2a-13e1-4ad7-80f2-e9318b99b21a", "kind": "event", "category": "process", "action": "execution-denied", "type": "start", "module": "bpf-lsm", "provider": "bprm-check-security", "sequence": "0"}, "host": {"hostname": "ubuntu-hirsute", "ip": ["10.0.2.15", "fe80::45:b3ff:fe9e:e735"], "mac": ["02:45:b3:9e:e7:35"], "uptime": "152672", "os": {"type": "linux", "name": "Ubuntu", "kernel": "5.11.0-rc6-bpf-lsm"}}, "process": {"pid": 136978, "entity_id": "7705686eca79aca811ef02dce446dc0c7de2f100ee55dafdada25f318e554023", "name": "ls", "ppid": 118774, "executable": "/usr/bin/ls", "args_count": "2", "start": "1612972701", "thread.id": "136978", "command_line": "ls --color=auto", "args": ["ls", "--color=auto"], "parent": {"pid": 118774, "entity_id": "bdb2d4ae705b5a33ecadde0047ab8e333e351cef0118ef52bb6777198b262b74", "name": "bash", "ppid": 118773, "start": "1612952897", "thread.id": "118774", "executable": "/usr/bin/bash"}}, "user": {"id": "1000", "name": "vagrant", "group": {"id": "1000", "name": "vagrant"}, "effective": {"id": "1000", "name": "vagrant", "group": {"id": "1000", "name": "vagrant"}}}}
```

## Kernel

The Vagrantfile boots a virtualbox VM with a custom Linux 5.11-rc6 build with BPF LSM kernel options
all enabled, a rust toolchain installed, and lldb for debugging builds with `rust-lldb`.

## Toolchains

The toolchain for this are all in Docker containers. The containers contain a clang 10-based compiler
that targets musl and libc++ in order to statically compile everything. As a result, you can't use any
Rust code that leverages `proc_macro` as this requires dynamically linking against glibc and gcc.
