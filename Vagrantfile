# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/hirsute64"
  config.vm.provider "virtualbox" do |v|
      v.memory = 2048
      v.cpus = 2
  end
  config.vm.provision "shell", inline: <<-SHELL
    curl -s -o linux.deb https://andrewstucki-bpf-lsm-deb.s3.amazonaws.com/linux-image-5.11.0-rc6-bpf-lsm_5.11.0-rc6-bpf-lsm-1_amd64.deb
    dpkg -i linux.deb
    rm linux.deb
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    apt-get install -y lldb
  SHELL
end
