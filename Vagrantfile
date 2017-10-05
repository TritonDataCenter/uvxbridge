# -*- mode: ruby -*-
# vi: set ft=ruby :

$machineConfigPriv = <<SCRIPT
pkg install -y \
	devel/git \
	editors/vim-lite \
	security/ca_root_nss \
	shells/bash

chsh -s /usr/local/bin/bash vagrant
chsh -s /usr/local/bin/bash root
SCRIPT

Vagrant.configure("2") do |config|
	config.vm.define "compile" do |vm|
		vm.vm.box = "FreeBSD-12.0-CURRENT-BHYVE-NODEBUG"

		vm.vm.provision "shell",
			inline: $machineConfigPriv,
			privileged: true

		vm.vm.provider "vmware_fusion" do |v|
			v.vmx["memsize"] = "8192"
			v.vmx["numvcpus"] = "4"
		end
	end
end
