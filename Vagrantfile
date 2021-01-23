# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "fedora/33-cloud-base"
  config.vm.box_version = "33.20201019.0"
  config.vm.provider "virtualbox" do |v|
      v.memory = 4096
      v.cpus = 4
  end
  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"
end
