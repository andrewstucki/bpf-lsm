# Example BPF LSM

This repo contains scripts and an example program to play around with BPF CO-RE modules and an LSM.

In order to be completely portable (assuming a new enough kernel), and to show how this would interop with a Rust program, the userspace components are written in a combination of Rust and C compiled with clang and linked against musl. The result should be that you can drop the output binary on any Linux 5.11+ kernel (for ringbuffer, LSM hook support, and inode local storage) and have it run.

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

In the first terminal you should see an event that looks like:

```json
{
  "@timestamp": "1613149814",
  "event": {
    "id": "11c3ce30-ff30-4e1f-bf59-ad8a4851fd9a",
    "kind": "event",
    "category": "process",
    "action": "execution-denied",
    "type": "start",
    "module": "bpf-lsm",
    "provider": "bprm-check-security",
    "sequence": "0"
  },
  "host": {
    "hostname": "ubuntu-hirsute",
    "ip": [
      "10.0.2.15",
      "fe80::45:b3ff:fe9e:e735"
    ],
    "mac": [
      "02:45:b3:9e:e7:35"
    ],
    "uptime": "238884",
    "os": {
      "type": "linux",
      "name": "Ubuntu",
      "kernel": "5.11.0-rc6-bpf-lsm"
    }
  },
  "process": {
    "pid": 214904,
    "entity_id": "698d5f16ba47c2808140278a9e4127f95f9cd514e8156a9572f8f262f7adb10a",
    "name": "ls",
    "ppid": 185070,
    "executable": "/usr/bin/ls",
    "args_count": "2",
    "start": "1613149814",
    "thread.id": "214904",
    "command_line": "ls --color=auto",
    "args": [
      "ls",
      "--color=auto"
    ],
    "parent": {
      "pid": 185070,
      "entity_id": "2adab6f443f9827e3473403b54d3808467a9bafb5950594d3beb67ca0d691c75",
      "name": "bash",
      "args_count": "1",
      "args": [
        "-bash"
      ],
      "ppid": 185069,
      "start": "1613121319",
      "thread.id": "185070",
      "executable": "/usr/bin/bash"
    }
  },
  "user": {
    "id": "1000",
    "name": "vagrant",
    "group": {
      "id": "1000",
      "name": "vagrant"
    },
    "effective": {
      "id": "1000",
      "name": "vagrant",
      "group": {
        "id": "1000",
        "name": "vagrant"
      }
    }
  }
}
```

If you want to test out file unlinking checks you can add a filter like `reject inode_unlink when file.path == "/home/vagrant/test.txt" and user.id == 0` and see it in action:

```bash
vagrant@ubuntu-hirsute:~$ touch test.txt
vagrant@ubuntu-hirsute:~$ rm test.txt
vagrant@ubuntu-hirsute:~$ touch test.txt
vagrant@ubuntu-hirsute:~$ sudo rm test.txt
rm: cannot remove 'test.txt': Operation not permitted
```

```json
{
  "@timestamp": "1613149749",
  "event": {
    "id": "5e3f9cd4-291a-469f-8b73-35eff181a917",
    "kind": "event",
    "category": "file",
    "action": "unlink-denied",
    "type": "deletion",
    "module": "bpf-lsm",
    "provider": "inode-unlink",
    "sequence": "3"
  },
  "host": {
    "hostname": "ubuntu-hirsute",
    "ip": [
      "10.0.2.15",
      "fe80::45:b3ff:fe9e:e735"
    ],
    "mac": [
      "02:45:b3:9e:e7:35"
    ],
    "uptime": "238819",
    "os": {
      "type": "linux",
      "name": "Ubuntu",
      "kernel": "5.11.0-rc6-bpf-lsm"
    }
  },
  "process": {
    "pid": 214840,
    "entity_id": "f70111f169cd7dea79d78de015ff48ebf6209292d77df45e227dbbdc97bfcac5",
    "name": "rm",
    "ppid": 214839,
    "executable": "/usr/bin/rm",
    "args_count": "2",
    "start": "1613149749",
    "thread.id": "214840",
    "command_line": "rm test.txt",
    "args": [
      "rm",
      "test.txt"
    ],
    "parent": {
      "pid": 214839,
      "entity_id": "2ad02210f987bee9cb66bf8949d83594d42d1d13fc647fbc255cab0c62ddb7b6",
      "name": "sudo",
      "args_count": "3",
      "args": [
        "sudo",
        "rm",
        "test.txt"
      ],
      "ppid": 185070,
      "start": "1613149749",
      "thread.id": "214839",
      "executable": "/usr/bin/sudo"
    }
  },
  "user": {
    "id": "0",
    "name": "root",
    "group": {
      "id": "0",
      "name": "root"
    },
    "effective": {
      "id": "0",
      "name": "root",
      "group": {
        "id": "0",
        "name": "root"
      }
    }
  },
  "file": {
    "name": "test.txt",
    "directory": "/home/vagrant",
    "path": "/home/vagrant/test.txt",
    "extension": "txt",
    "inode": "72843"
  }
}
```

## Kernel

The Vagrantfile boots a virtualbox VM with a custom Linux 5.11-rc6 build with BPF LSM kernel options
all enabled, a rust toolchain installed, and lldb for debugging builds with `rust-lldb`.

## Toolchains

The toolchain for this are all in Docker containers. The containers contain a clang 10-based compiler
that targets musl and libc++ in order to statically compile everything. As a result, you can't use any
Rust code that leverages `proc_macro` as this requires dynamically linking against glibc and gcc.
