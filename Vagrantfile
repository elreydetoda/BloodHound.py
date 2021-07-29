Vagrant.configure("2") do |config|
  # added docker w/snap
  # built docker image for this project
  # https://unix.stackexchange.com/questions/255484/how-can-i-bridge-two-interfaces-with-ip-iproute2#255489
  # sudo ip link add docker1 type bridge
  # adding network connectivity for that bridge
  # ip address add 192.168.33.9/24 dev docker1
  # sudo ip link set dev eth1 master docker1
  # https://maxammann.org/posts/2020/04/routing-docker-container-over-vpn/
  # docker network create -d bridge -o 'com.docker.network.bridge.name'='docker1' --subnet=172.18.0.1/16 domain
  config.vm.define "atk" do |attacker|
    attacker.vm.box = "bento/ubuntu-20.04"
    attacker.vm.network "private_network", ip: "192.168.33.10"
    attacker.vm.synced_folder ".", "/home/vagrant/vagrant"
    attacker.vm.provider "virtualbox" do |vb|
      vb.cpus = "4"
      vb.memory = "4096"
    end
  end
  config.vm.define "dc" do |dc|
    # built with this project: https://github.com/boxcutter/windows
    dc.vm.box = "eval-win2k16"
    dc.vm.network "private_network", ip: "192.168.33.11"
    dc.vm.synced_folder ".", "/vagrant", disabled: true
    dc.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.cpus = "2"
      vb.memory = "4096"
    end
  end
  config.vm.define "host" do |host|
    # built with this project: https://github.com/boxcutter/windows
    host.vm.box = "eval-win10"
    host.vm.network "private_network", ip: "192.168.33.12"
    host.vm.synced_folder ".", "/vagrant", disabled: true
    host.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.cpus = "2"
      vb.memory = "4096"
    end
  end
end
