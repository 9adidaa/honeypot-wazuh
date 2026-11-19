# -*- mode: ruby -*-
# vi: set ft=ruby :
# =============================================================================
# Déploiement complet du lab honeypot, de A à Z, en une commande :
#
#     vagrant up
#
# 1. désactive le DHCP VirtualBox du réseau host-only 192.168.56.0/24
# 2. crée SRV01 (Wazuh manager + indexer + dashboard) et NIX01 (honeypot + agent)
# 3. fixe les IP (192.168.56.102 / .101), le hostname, /etc/hosts
# 4. vérifie l'OS (Ubuntu 22.04/24.04), la RAM, le disque, Internet
# 5. installe Wazuh, lance deploy/srv01.sh puis deploy/nix01.sh, puis les tests
#
# Variables optionnelles : SRV01_MEM (Mo, défaut 6144), SRV01_CPUS (défaut 2),
#                          NIX01_MEM (défaut 2048), HP_BOX (défaut bento/ubuntu-24.04)
# =============================================================================
require "open3"

Vagrant.require_version ">= 2.3.0"

BOX        = ENV.fetch("HP_BOX", "bento/ubuntu-24.04")
NET        = "192.168.56"
SRV01_IP   = "#{NET}.102"
NIX01_IP   = "#{NET}.101"
SRV01_MEM  = ENV.fetch("SRV01_MEM", "6144").to_i
SRV01_CPUS = ENV.fetch("SRV01_CPUS", "2").to_i
NIX01_MEM  = ENV.fetch("NIX01_MEM", "2048").to_i

# --- VBoxManage (aussi sous Windows quand il n'est pas dans le PATH) ---------
def vboxmanage
  candidates = ["VBoxManage"]
  if Vagrant::Util::Platform.windows?
    base = ENV["VBOX_MSI_INSTALL_PATH"] || ENV["VBOX_INSTALL_PATH"] || 'C:\Program Files\Oracle\VirtualBox'
    candidates.unshift(File.join(base, "VBoxManage.exe"))
  end
  candidates.find { |c| system(c, "--version", out: File::NULL, err: File::NULL) }
end

# --- Désactive tout serveur DHCP VirtualBox sur 192.168.56.x ----------------
def disable_hostonly_dhcp(prefix)
  vbm = vboxmanage
  unless vbm
    puts "[!] VBoxManage introuvable : DHCP host-only non vérifié"
    return
  end
  out, _status = Open3.capture2(vbm, "list", "dhcpservers")
  out.split(/\r?\n\s*\r?\n/).each do |blk|
    name    = blk[/^NetworkName:\s*(.+)$/, 1]&.strip
    ip      = blk[/^Dhcpd IP:\s*(.+)$/, 1]&.strip
    enabled = blk[/^Enabled:\s*(.+)$/, 1]&.strip
    next unless name && ip && ip.start_with?("#{prefix}.")
    if enabled.to_s =~ /yes/i
      ok = system(vbm, "dhcpserver", "modify", "--network=#{name}", "--disable")
      puts(ok ? "[+] DHCP VirtualBox désactivé sur #{name} (#{ip})" : "[!] Impossible de désactiver le DHCP de #{name}")
    else
      puts "[=] DHCP déjà désactivé sur #{name}"
    end
  end
end

Vagrant.configure("2") do |config|
  config.vm.box = BOX
  config.vm.box_check_update = false
  config.vm.boot_timeout = 600
  config.vm.synced_folder ".", "/vagrant"

  # DHCP coupé avant la création des VM, et revérifié après (le réseau
  # host-only peut être créé par Vagrant pendant le "up")
  config.trigger.before :up do |t|
    t.info = "Vérification du DHCP VirtualBox sur #{NET}.0/24"
    t.ruby { |_env, _machine| disable_hostonly_dhcp(NET) }
  end
  config.trigger.after :up do |t|
    t.ruby { |_env, _machine| disable_hostonly_dhcp(NET) }
  end

  common_env = { "SRV01_IP" => SRV01_IP, "NIX01_IP" => NIX01_IP }

  # ---------------------------------------------------------------- SRV01 --
  # Défini en premier : l'agent de NIX01 a besoin du manager pour s'enrôler.
  config.vm.define "srv01", primary: true do |s|
    s.vm.hostname = "srv01"
    s.vm.network "private_network", ip: SRV01_IP
    s.vm.provider "virtualbox" do |vb|
      vb.name   = "SRV01"
      vb.memory = SRV01_MEM
      vb.cpus   = SRV01_CPUS
    end
    s.vm.provision "shell", path: "deploy/vagrant/provision.sh", args: ["srv01"], env: common_env
  end

  # ---------------------------------------------------------------- NIX01 --
  config.vm.define "nix01" do |n|
    n.vm.hostname = "nix01"
    n.vm.network "private_network", ip: NIX01_IP
    n.vm.provider "virtualbox" do |vb|
      vb.name   = "NIX01"
      vb.memory = NIX01_MEM
      vb.cpus   = 1
    end
    n.vm.provision "shell", path: "deploy/vagrant/provision.sh", args: ["nix01"], env: common_env
  end
end
