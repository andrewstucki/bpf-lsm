# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "fedora/33-cloud-base"
  config.vm.box_version = "33.20201019.0"
  config.vm.provider "virtualbox" do |v|
      v.memory = 2048
      v.cpus = 2
  end
  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"
  config.vm.provision "shell", inline: <<-SCRIPT
tee -a /etc/yum.repos.d/bpf-kernel.repo << END
[bpf-kernel]
baseurl = https://andrewstucki-bpf-lsm.s3.amazonaws.com
enabled = 1
gpgcheck = 0
name = BPF Kernel
repo_gpgcheck = 0
END
dnf check-upgrade
dnf install kernel-5.10.9-202.local.fc33 -y
echo '* - memlock 4196' >> /etc/security/limits.conf
SCRIPT
end
