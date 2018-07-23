#!/bin/bash
#
# linux-security-baseline.sh - Linux Security Baseline based on CIS Benchmarks
#
# Version....: 1.0.0-beta 
# Site.......: https://github.com/daniel-armbrust/linux-security-baseline
# Author.....: Daniel Armbrust <darmbrust@gmail.com>
#
# Tested on:
#   Red Hat Enterprise Linux Server release 7.5 (Maipo) - 3.10.0-862.el7.x86_64
#  
# 
#  LICENCE
#  =======
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#

#
# Globals
#
BACKUP_DIR=''
SCRIPT_VERSION='1.0.0-beta'
CIS_BENCHMARK_LIST=('CIS Distribution Independent Linux - v.1.1.0 - 12-26-2017')

# Firewall Ports
IPT_TCP_ALLOW_PORT_LIST=('22')
IPT6_TCP_ALLOW_PORT_LIST=('22')

# Command line flags
ENABLE_FIREWALL=0
ENABLE_SELINUX=0
ENABLE_AIDE=0
ROOT_MAILTO=""
REBOOT_PASSWORD=0


function splash_screen() {
  #
  # http://www.patorjk.com/software/taag/
  #
  echo ' _     _                                                                      '
  echo '| |   (_)                                                                     '
  echo '| |    _ _ __  _   ___  __                                                    '
  echo "| |   | | '_ \| | | \ \/ /                                                    "
  echo '| |___| | | | | |_| |>  <                                                     '
  echo '\_____/_|_| |_|\__,_/_/\_\                                                    '
  echo ''
  echo ' _____                      _ _          ______                _ _            '
  echo '/  ___|                    (_) |         | ___ \              | (_)           '
  echo '\ .--.  ___  ___ _   _ _ __ _| |_ _   _  | |_/ / __ _ ___  ___| |_ _ __   ___ '
  echo " .--. \\/ _ \\/ __| | | | '__| | __| | | | | ___ \\/ _' / __|/ _ \\ | | '_ \\ / _ \\"
  echo '/\__/ /  __/ (__| |_| | |  | | |_| |_| | | |_/ / (_| \__ \  __/ | | | | |  __/'
  echo '\____/ \___|\___|\__,_|_|  |_|\__|\__, | \____/ \__,_|___/\___|_|_|_| |_|\___|'
  echo '                                   __/ |                                      '
  echo '                                  |___/                                       '
  echo ''

  echo -e "\nLinux Security Baseline - $SCRIPT_VERSION"
  echo "Author: Daniel Armbrust <darmbrust@gmail.com>"

  echo -e "\nCIS Benchmarks - https://www.cisecurity.org/cis-benchmarks/" 

  i=0
  while [ $i -lt ${#CIS_BENCHMARK_LIST[*]} ]; do
    echo -e " * ${CIS_BENCHMARK_LIST[$i]}" 
    let i+=1
  done
}

function show_help() {
  #
  # Help
  #
  local help_text="
 
   Help
   ====

   Usage: $(basename "$0") [OPTION]...
   
  
   -b, --backup-dir        specify a directory for backup
   --root-mailto           person who should get root's mail

   --enable-boot-password  grub boot password. If this option is enabled, you will need to enter
                           a password every time you reboot your Linux box. (default: disabled)
         
   --enable-aide           configure and enable AIDE.
   --enable-firewall       apply iptables/ip6tables firewall rules (default: disabled)
   --enable-selinux        configure and enable SELinux (default: disabled)

   -h, --help           display this help and exit
   -V, --version        output version information and exit

   EXAMPLES:
     $(basename "$0") -b /tmp/backup --root-mailto notify@your-email-domain.br
     $(basename "$0") -b /var/backups --root-mailto notify@your-email-domain.br --enable-aide

   FOR MORE INFORMATION (https://daniel-armbrust.github.io/linux-security-baseline/)
"
   splash_screen
   echo "$help_text"
}

function do_backup() {
  # 
  # System Backup
  #
  local file="$1"
  local date_str="$(date +%m%d%Y-%s)"
  local temp_file=$(mktemp)
  
  local file_or_dir_list=('/etc/modprobe.d/BASELINE.conf' '/etc/sysctl.conf' '/etc/sysctl.d/'
    '/etc/fstab' '/boot/grub2/grub.cfg' '/boot/grub/menu.lst' '/etc/security/limits.conf'
    '/etc/security/limits.d/' '/etc/sysconfig/init' '/etc/sysconfig/boot' 
    '/etc/default/grub' '/etc/sysctl.conf' '/etc/sysctl.d/' '/etc/ntp.conf' '/etc/sysconfig/ntpd'
    '/etc/sysconfig/ntp' '/etc/chrony.conf' '/etc/pam.d/system-auth' '/etc/pam.d/password-auth'
    '/etc/security/pwquality.conf' '/etc/issue' '/etc/issue.net' '/etc/dconf/profile/gdm'
    '/etc/motd' '/etc/selinux/config' '/etc/sysconfig/iptables' '/etc/sysconfig/ip6tables'
    '/etc/audit/auditd.conf' '/etc/audit/audit.rules' '/etc/rsyslog.conf' '/etc/rsyslog.d/'
    '/etc/cron.allow' '/etc/at.allow' '/etc/cron.deny' '/etc/ssh/sshd_config' '/etc/pam.d/'
    '/etc/pam.conf' '/etc/passwd' '/etc/shadow' '/etc/group' '/etc/shells' '/etc/login.defs')

  mkdir -p "$BACKUP_DIR/"
  mv -f "$temp_file" "$BACKUP_DIR/" 2>/dev/null
   
  if [ $? -ne 0 ]; then
    echo " [ERROR] The backup directory \"$BACKUP_DIR\" cannot be used! Exiting ..."
    rm -f "$temp_file" 
    exit 1
  else
    setfacl -b "$BACKUP_DIR/"
    chown root: "$BACKUP_DIR/"
    chmod 0700 "$BACKUP_DIR/"
    rm -f "$BACKUP_DIR/tmp.*"
  fi

  echo "[!!] Doing backup ..."
  
  tar --ignore-failed-read --acls --keep-directory-symlink \
     -czpf "$BACKUP_DIR/baseline-backup-$date_str.tar.gz" ${file_or_dir_list[*]} &>/dev/null
  
  # Test the archive before continue
  tar -tzf "$BACKUP_DIR/baseline-backup-$date_str.tar.gz" &>/dev/null
  
  if [ $? -ne 0 ]; then
    echo "[ERROR] The backup is corrupted. IT'S NOT SAFE TO CONTINUE!"
    echo "Exiting ..."
    exit 1
  fi  
}

function _restart_service() {
  #
  # Restart the specified service.
  #
  local service="$1"

  if [ ! -z "$(which service 2>/dev/null)" ]; then
    # TODO: service -q ?
    service "$service" restart
  elif [ ! -z "$(which systemctl 2>/dev/null)" ]; then
    systemctl -q restart "$service"
  else
    echo " [!!] Cannot restart service \"$service\""
  fi
}

function _generate_random_password() {
  #
  # Internal function that generate a random password.
  #
  local rand_passwd=''
  local salt=''
  local crypt_passwd=''

  # https://www.howtogeek.com/howto/30184/10-ways-to-generate-a-random-password-from-the-command-line/
  # https://edvoncken.net/2011/03/tip-encrypted-passwords-just-add-salt/

  if [ ! -z "$(which openssl 2>/dev/null)" ]; then
    rand_passwd="$(tr -cd '[:alnum:]' < /dev/urandom | fold -w12 | head -n1)"
    salt="$(tr -cd '[:alnum:]' < /dev/urandom | fold -w6 | head -n1)"
    crypt_passwd="$(openssl passwd -1 -salt "$salt" "$rand_passwd")"
    
    echo "$rand_passwd:$crypt_passwd"
  else
    echo -n ""
  fi
}

function _install_package() {
  #
  #   Function that checks if a specific package was installed. If was 
  # not installed, the installation is forced.
  #
  local package="$1"

  if [ ! -z "$(which yum 2>/dev/null)" ]; then
    rpm -q "$package" &>/dev/null

    if [ $? -eq 0 ]; then
      echo -e " [--] The package \"$package\" is already installed on this system.\n"
    else
      echo " [!!] The package \"$package\" was NOT INSTALLED!"
      echo -e " [!!] Installing the \"$package\" ... \n"
      yum -q -y install "$package" 1>/dev/null
    fi   

  elif [ ! -z "$(which apt-get 2>/dev/null)" ]; then
    # TODO: dpks -q ???
    dpkg -s "$package" &>/dev/null

    if [ $? -eq 0 ]; then
      echo -e " [--] The package \"$package\" is already installed on this system.\n"
    else
      echo " [!!] The package \"$package\" was NOT INSTALLED!\n"
      echo -e " [!!] Installing the \"$package\" ... \n"
      # TODO: apt-get -q ???
      apt-get -y install "$package"
    fi   
  
  else
     echo -e " [!!] Could NOT INSTALL the package \"$package\".\n"
  fi
}

function _uninstall_package() {
  #
  # Uninstall the specific package. 
  #
  local packages="$1"
  
  echo "$packages" | tr ',' '\n' | while read package; do
  
    if [ ! -z "$(which yum 2>/dev/null)" ]; then
      yum -q -y remove "$package" 1>/dev/null
    
      if [ $? -ne 0 ]; then
        echo -e "[!!] Could NOT REMOVE the package \"$package\".\n"
      fi

    elif [ ! -z "$(which apt-get 2>/dev/null)" ]; then
      # TODO: apt-get -q ??
      apt-get -y remove "$package" 1>/dev/null
    
      if [ $? -ne 0 ]; then
        echo -e "[!!] Could NOT REMOVE the package \"$package\".\n"
      fi

    else
      echo -e "[!!] Could NOT REMOVE the package \"$package\".\n"   
    fi
    
  done
}

function _disable_service() {
  #
  # Function that disable service.
  #
  local service="$1"

  if [ ! -z "$(which systemctl 2>/dev/null)" ]; then
    systemctl -q disable "$service"
  else
    if [ ! -z "$(which chkconfig 2>/dev/null)" ]; then
       # TODO: -q ??
      chkconfig "$service" off 1>/dev/null
    elif [ ! -z "$(which update-rc.d 2>/dev/null)" ]; then
      # TODO: -q ??
      update-rc.d "$service" disable 1>/dev/null
    else
      echo -e "[!!] Could NOT DISABLE the service \"$service\".\n"
    fi

    find /etc/rc*.d | grep '/S' | grep "$service" | while read enable_link; do
      disable_link="$(echo -n "$enable_link" | sed '0,/S/s//K/')"
      mv -f "$enable_link" "$disable_link"
    done

  fi
}

function _enable_service() {
  #
  # Function that enable service.
  #
  local service="$1"

  if [ ! -z "$(which systemctl 2>/dev/null)" ]; then
    systemctl -q enable "$service"
  else
    if [ ! -z "$(which chkconfig 2>/dev/null)" ]; then
      chkconfig "$service" on 1>/dev/null
    elif [ ! -z "$(which update-rc.d 2>/dev/null)" ]; then
      update-rc.d "$service" enable 1>/dev/null
    else
      echo -e "[!!] Could ENABLE the service \"$service\".\n"
    fi
  fi
}

function _disable_inetd_xinetd_service() {
  #
  # Function that disable inetd or xinetd service.
  #
  local service="$1"

  grep -R "^service $service" /etc/xinetd.* 2>/dev/null | cut -f1 -d":" | while read xinetd_file; do
    sed -i '/disable/c\disable = yes' $xinetd_file
  done

  grep -HR  "^$service" /etc/inetd.* 2>/dev/null | cut -f1 -d":" | while read inetd_file; do
    sed -i "s/^$service/#$service/" $inetd_file
  done
}

function _return_uid_min_value() {
  #
  # Return min value for automatic uid selection in useradd from /etc/login.defs file.
  #
  local uid_min="$(cat /etc/login.defs | grep "^UID_MIN" | awk '{print $2}')"

  if [ -z "$uid_min" ]; then
    uid_min='500'
  fi

  echo -n "$uid_min"
}

function _return_last_free_uid() {
  #
  # Return last FREE UID number from /etc/passwd.
  #
  local last_uid=$(cat /etc/passwd | awk -F: '{print $3}' | sort -n | tail -1 | head -1)
  local min_uid_value=$(_return_uid_min_value)
  local last_free_uid=-1

  while [ true ]; do
    last_free_uid=$(expr $last_uid - 1)

    if [ -z "$(cat /etc/passwd | awk -F: '{print $3}' | grep "^$last_uid$")" ]; then
      break
    fi
  done

  if [ $last_free_uid -gt $min_uid_value ]; then
    echo "$last_free_uid"
  else
    echo -1
  fi
}

function _audit_rules_32bits() {
  #
  # For 32 bit systems, only one rule is needed. 
  #
  local rules_file="$1"
  local uid_min="$2"

  cat <<EOT >"$rules_file"

-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k timechange 
-a always,exit -F arch=b32 -S clock_settime -k time-change 
-w /etc/localtime -p wa -k time-change 

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale 
-w /etc/sysconfig/network -p wa -k system-locale 

-w /etc/selinux/ -p wa -k MAC-policy 
-w /usr/share/selinux/ -p wa -k MAC-policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

-w /var/log/faillog -p wa -k logins 
-w /var/log/lastlog -p wa -k logins 
-w /var/log/tallylog -p wa -k logins

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins 
-w /var/log/btmp -p wa -k logins 

-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=$uid_min -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=$uid_min -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$uid_min -F auid!=4294967295 -k perm_mod 

-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=$uid_min -F auid!=4294967295 -k access 
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=$uid_min -F auid!=4294967295 -k access

-a always,exit -F arch=b32 -S mount -F auid>=$uid_min -F auid!=4294967295 -k mounts

-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=$uid_min -F auid!=4294967295 -k delete

-w /etc/sudoers -p wa -k scope 
-w /etc/sudoers.d/ -p wa -k scope 
-w /var/log/sudo.log -p wa -k actions 

-w /sbin/insmod -p x -k modules 
-w /sbin/rmmod -p x -k modules 
-w /sbin/modprobe -p x -k modules -a always,exit -F arch=b32 -S init_module -S delete_module -k modules 

-e 2
EOT

}

function _audit_rules_64bits() {
  #
  #   For 64 bit systems that have arch as a rule parameter, you will need two rules: 
  # one for 64 bit and one for 32 bit systems
  #
  local rules_file="$1"
  local uid_min="$2"

  cat <<EOT >"$rules_file"

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change 
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k timechange 
-a always,exit -F arch=b64 -S clock_settime -k time-change 
-a always,exit -F arch=b32 -S clock_settime -k time-change 
-w /etc/localtime -p wa -k time-change 

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale 
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale 
-w /etc/issue -p wa -k system-locale 
-w /etc/issue.net -p wa -k system-locale 
-w /etc/hosts -p wa -k system-locale 
-w /etc/sysconfig/network -p wa -k system-locale

-w /etc/selinux/ -p wa -k MAC-policy 
-w /usr/share/selinux/ -p wa -k MAC-policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

-w /var/log/faillog -p wa -k logins 
-w /var/log/lastlog -p wa -k logins 
-w /var/log/tallylog -p wa -k logins

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins 
-w /var/log/btmp -p wa -k logins 

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=$uid_min -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=$uid_min -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=$uid_min -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=$uid_min -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$uid_min -F auid!=4294967295 -k perm_mod -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$uid_min -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=$uid_min -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=$uid_min -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=$uid_min -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=$uid_min -F auid!=4294967295 -k access

-a always,exit -F arch=b64 -S mount -F auid>=$uid_min -F auid!=4294967295 -k mounts 
-a always,exit -F arch=b32 -S mount -F auid>=$uid_min -F auid!=4294967295 -k mounts 

-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=$uid_min -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=$uid_min -F auid!=4294967295 -k delete 

-w /etc/sudoers -p wa -k scope 
-w /etc/sudoers.d/ -p wa -k scope 
-w /var/log/sudo.log -p wa -k actions 

-w /sbin/insmod -p x -k modules 
-w /sbin/rmmod -p x -k modules 
-w /sbin/modprobe -p x -k modules 
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules 

-e 2
EOT

}

function hardening_mta() {
  #
  # Hardening the mail system.
  #
  if [ -f /etc/postfix/main.cf ]; then
    sed -i '/^inet_interfaces/c\inet_interfaces = loopback-only' /etc/postfix/main.cf
    _restart_service postfix
  fi

  if [ -z "$(grep "^root:" /etc/aliases)" ]; then
    echo "root: $ROOT_MAILTO" >>/etc/aliases
  else
    sed -i "/^root:/c\root: $ROOT_MAILTO" /etc/aliases
  fi

  # TODO: sendmail config
  # TODO: postfix not installed?

  which newaliases &>/dev/null && newaliases
}

function hardening_kernel_modules() {
  #
  # 1.1.1 Disable unused filesystems 
  # 3.5 Uncommon Network Protocols 
  #
  local security_item_list=(
    '1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored):cramfs'
    '1.1.1.2 Ensure mounting of freevxfs filesystems is disabled (Scored):freevxfs'
    '1.1.1.3 Ensure mounting of jffs2 filesystems is disabled (Scored):jffs2'
    '1.1.1.4 Ensure mounting of hfs filesystems is disabled (Scored):hfs'
    '1.1.1.6 Ensure mounting of squashfs filesystems is disabled (Scored):squashfs'
    '1.1.1.7 Ensure mounting of udf filesystems is disabled (Scored):udf'
    '1.1.1.8 Ensure mounting of FAT filesystems is disabled (Scored):vfat'
    '3.5.1 Ensure DCCP is disabled (Not Scored):dccp'
    '3.5.2 Ensure SCTP is disabled (Not Scored):sctp'
    '3.5.3 Ensure RDS is disabled (Not Scored):rds'
    '3.5.4 Ensure TIPC is disabled (Not Scored):tipc'
  )

  if [ ! -d "/etc/modprobe.d" ]; then
    mkdir /etc/modprobe.d
  fi 

  if [ ! -f "/etc/modprobe.d/BASELINE.conf" ]; then
    # TODO: put header line
    touch "/etc/modprobe.d/BASELINE.conf"
  fi

  local title=''
  local kmod=''
  local i=0

  while [ $i -lt ${#security_item_list[*]} ]; do
    title="$(echo -n "${security_item_list[$i]}" | cut -f1 -d':')"
    kmod="$(echo -n "${security_item_list[$i]}" | cut -f2 -d':')"
    
    echo "$title"
    
    if [ -z "$(grep "^install $kmod /bin/true$" /etc/modprobe.d/BASELINE.conf)" ]; then
      echo "install $kmod /bin/true" >> /etc/modprobe.d/BASELINE.conf
    fi
    
    rmmod $kmod 2>/dev/null

    let i+=1
  done
}

function partition_hardening() {
  #
  # Hardening: /tmp 
  #  - 1.1.2 Ensure separate partition exists for /tmp (Scored) 
  #  - 1.1.3 Ensure nodev option set on /tmp partition (Scored) 
  #  - 1.1.4 Ensure nosuid option set on /tmp partition (Scored)
  #  - 1.1.5 Ensure noexec option set on /tmp partition (Scored)
  #  
  # Hardening: /var
  #  - 1.1.6 Ensure separate partition exists for /var (Scored) 
  #
  # Hardening: /var/tmp
  #  - 1.1.7 Ensure separate partition exists for /var/tmp (Scored)
  #  - 1.1.8 Ensure nodev option set on /var/tmp partition (Scored)
  #  - 1.1.9 Ensure nosuid option set on /var/tmp partition (Scored)
  #  - 1.1.10 Ensure noexec option set on /var/tmp partition (Scored) 
  #  - 1.1.11 Ensure noexec option set on /var/tmp partition (Scored)
  #  - 1.1.12 Ensure noexec option set on /var/tmp partition (Scored)
  #  - 1.1.13 Ensure noexec option set on /var/tmp partition (Scored)
  #  - 1.1.14 Ensure noexec option set on /var/tmp partition (Scored) 
  #
  # Hardening: /var/log
  #  - 1.1.15 Ensure separate partition exists for /var/log (Scored) 
  #  - 1.1.16 Ensure separate partition exists for /var/log/audit (Scored)
  #  
  # Hardening: /home
  #  - 1.1.17 Ensure separate partition exists for /home (Scored) 
  #  - 1.1.18 Ensure nodev option set on /home partition (Scored) 
  #  - 1.1.19 Ensure nodev option set on /dev/shm partition (Scored)
  #  - 1.1.20 Ensure nosuid option set on /dev/shm partition (Scored)
  #  - 1.1.21 Ensure noexec option set on /dev/shm partition (Scored)
  #  
  # TODO Hardening: removable media  
  #  - 1.1.22 Ensure nodev option set on removable media partitions (Not Scored)
  #  - 1.1.23 Ensure nosuid option set on removable media partitions (Not Scored)
  #  - 1.1.24 Ensure noexec option set on removable media partitions (Not Scored)
  #
  
  local partition_list=(
    '\/tmp:rw,nosuid,nodev,noexec,relatime'
    '\/var\/tmp:rw,nosuid,nodev,noexec,relatime'
    '\/var\/log:rw,nosuid,nodev,noexec,relatime'
    '\/var\/log\/audit:rw,nosuid,nodev,noexec,relatime'
    '\/home:rw,nosuid,nodev'
    '\/dev\/shm:rw,nodev,nosuid,noexec'
    '\/boot:ro'
  )

  local temp_file=$(mktemp)
  local partition=''
  local mount_options=''
  local fstab_line='' 
  local line_num=''
  local line_str=''
  local str=''

  local i=0
  while [ $i -lt ${#partition_list[*]} ]; do
    partition="$(echo -n "${partition_list[$i]}" | cut -f1 -d':')"
    mount_options="$(echo -n "${partition_list[$i]}" | cut -f2 -d':')"
    fstab_line="$(grep -n " $partition" /etc/fstab)"

    if [ ! -z "$line" ]; then
      line_num=$(echo -n "$fstab_line" | cut -f1 -d':')
      line_str=$(echo -n "$fstab_line" | cut -f2 -d':')

      sed "/ $partition/d" "/etc/fstab" >$temp_file
      echo "$line_str" | awk -v ops=$mount_options '{print $1,$2,$3,ops,$5,$6}' >/etc/fstab
      mount -o remount,$mount_options $partition 1>/dev/null

    else
      str="$(echo -n "$partition" | tr -d '\\')"
      echo -e " [!!] The partition \"$str\" not mounted separately!"
    fi

    let i+=1
  done

  rm -f "$temp_file"
}

function install_required_packages() {
  #
  # 1.3 Filesystem Integrity Checking
  # 1.3.1 Ensure AIDE is installed (Scored) 
  #
  local security_item_list=(
   '1.3.1 Ensure AIDE is installed (Scored):aide' 
   '3.4.1 Ensure TCP Wrappers is installed (Scored):tcpd'
   '4.2.3 Ensure rsyslog or syslog-ng is installed (Scored):rsyslog'
  )

  local i=0
  local title=''
  local package=''
 
  while [ $i -lt ${#security_item_list[*]} ]; do
    title="$(echo -n "${security_item_list[$i]}" | cut -f1 -d ':')"
    package="$(echo -n "${security_item_list[$i]}" | cut -f2 -d ':')"

    echo "$title"
    _install_package "$package"   

    let i+=1
  done
}

function hardening_firewall() {
  #
  # 3.6 Firewall Configuration
  #
  echo "3.6.1 Ensure iptables is installed (Scored)"

  _install_package "iptables"
  _install_package "iptables-services"

  echo -e "\n3.6.2 Ensure default deny firewall policy (Scored)"
  echo "3.6.3 Ensure loopback traffic is configured (Scored)"
  echo "3.6.4 Ensure outbound and established connections are configured (Not Scored)"
  echo "3.6.5 Ensure firewall rules exist for all open ports (Scored)"

  cat <<EOT >/etc/sysconfig/iptables
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT -s 127.0.0.0/8 -j DROP
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
EOT
  
  local i=0
  local tcp_port=""

  while [ $i -lt ${#IPT_TCP_ALLOW_PORT_LIST[*]} ]; do
    tcp_port="${IPT_TCP_ALLOW_PORT_LIST[$i]}"
    echo "-A INPUT -p tcp --dport $tcp_port -m state --state NEW -j ACCEPT" >>/etc/sysconfig/iptables
    let i+=1
  done
  
  echo "COMMIT" >>/etc/sysconfig/iptables

  cat <<EOT >/etc/sysconfig/ip6tables
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p ipv6-icmp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
EOT

  i=0
  while [ $i -lt ${#IPT6_TCP_ALLOW_PORT_LIST[*]} ]; do
    tcp_port="${IPT6_TCP_ALLOW_PORT_LIST[$i]}"
    echo "-A INPUT -p tcp --dport $tcp_port -m state --state NEW -j ACCEPT" >>/etc/sysconfig/ip6tables
    let i+=1
  done

  echo "COMMIT" >>/etc/sysconfig/ip6tables

  _restart_service iptables
}

function hardening_logging_auditing() {
  #
  # 4 Logging and Auditing 
  #    rsyslog / logwatch
  #    auditd / aureport
  #
  local audit_conf_file="/etc/audit/auditd.conf"
  local audit_rules_file="/etc/audit/audit.rules"
  
  echo "4.1.1.1 Ensure audit log storage size is configured (Not Scored)"
  sed -i '/^max_log_file/c\max_log_file = 8' $audit_conf_file

  echo "4.1.1.2 Ensure system is disabled when audit logs are full (Scored)"
  sed -i '/^space_left_action/c\space_left_action = email' $audit_conf_file
  sed -i '/^action_mail_acct/c\action_mail_acct = root' $audit_conf_file
  sed -i '/^admin_space_left_action/c\admin_space_left_action = email' $audit_conf_file

  echo "4.1.1.3 Ensure audit logs are not automatically deleted (Scored)"
  sed -i '/^max_log_file_action/c\max_log_file_action = email' $audit_conf_file

  echo "4.1.4 Ensure events that modify date and time information are collected (Scored)"
  echo "4.1.5 Ensure events that modify user/group information are collected (Scored)"
  echo "4.1.6 Ensure events that modify the system's network environment are collected (Scored)"
  echo "4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected (Scored)"
  echo "4.1.8 Ensure login and logout events are collected (Scored)"
  echo "4.1.9 Ensure session initiation information is collected (Scored)"
  echo "4.1.10 Ensure discretionary access control permission modification events are collected (Scored)"
  echo "4.1.11 Ensure unsuccessful unauthorized file access attempts are collected (Scored)"
  echo "4.1.13 Ensure successful file system mounts are collected (Scored)"
  echo "4.1.15 Ensure changes to system administration scope (sudoers) is collected (Scored)"
  echo "4.1.16 Ensure system administrator actions (sudolog) are collected (Scored)"
  echo "4.1.17 Ensure kernel module loading and unloading is collected (Scored)"
  echo "4.1.18 Ensure the audit configuration is immutable (Scored)"

  local uid_min="$(_return_uid_min_value)"

  if [ "$(lscpu | grep "^Architecture" | awk '{print $2}')" == 'x86_64' ]; then
    _audit_rules_64bits "$audit_rules_file" "$uid_min"
  else
    _audit_rules_32bits "$audit_rules_file" "$uid_min"
  fi

  echo "4.1.12 Ensure use of privileged commands is collected (Scored)"

  df --local | grep "^/" | awk '{print $6}' | while read partiton; do
    find "$partiton" -xdev \( -perm -4000 -o -perm -2000 \) -type f | while read f; do
      echo "-a always,exit -F path=$f -F perm=x -F auid>=$uid_min -F auid!=4294967295 -k privileged" >> "$audit_rules_file"
    done
  done

  # TODO: 4.3 Ensure logrotate is configured (Not Scored)
}

function hardening_at_cron() {
  #
  # 5.1.8 Ensure at/cron is restricted to authorized users (Scored)  
  #
  local temp_file="$(mktemp)"

  echo "5.1.8 Ensure at/cron is restricted to authorized users (Scored)"

  test -f /etc/cron.deny && rm -f /etc/cron.deny
  test -f /etc/at.deny && rm -f /etc/at.deny

  test ! -f /etc/cron.allow && touch /etc/cron.allow
  test ! -f /etc/at.allow && touch /etc/at.allow

  ls -1 /etc/cron.allow /etc/at.allow | while read f; do

     if [ -f "$f" ]; then
       if [ -z "$(grep "^root$" "$f")" ]; then
         cat "$f" > "$temp_file"
         echo 'root' > "$f"
         cat "$temp_file" >> "$f"
       fi
     else
       echo 'root' > "$f"
     fi

  done

  rm -f "$temp_file"
}

function hardening_package_manager() {
  #
  # 1.2 Configure Software Updates 
  # 1.2.1 Ensure package manager repositories are configured (Not Scored
  # 1.2.2 Ensure GPG keys are configured (Not Scored) 
  # 1.8 Ensure updates, patches, and additional security software are installed (Not Scored) 
  #  
  echo "1.8 Ensure updates, patches, and additional security software are installed (Not Scored)"
  echo -e " [!!] Updating your system. Be patient...\n"

  if [ ! -z "$(which yum 2>/dev/null)" ]; then
    yum -q -y update
  elif [ ! -z "$(which apt-get 2>/dev/null)" ]; then
    # TODO: apt-get -q ??
    apt-get -y upgrade
  else
    echo -e " [!!] Package manger not found or not supported!"
  fi
}

function hardening_user_group() {
  #
  # 6.2 User and Group Settings 
  #
  local min_uid_value=$(_return_uid_min_value)

  echo "6.2.1 Ensure password fields are not empty (Scored)"
  cat /etc/shadow | awk -F: '($2 == "") {print $1}' | xargs --no-run-if-empty -n 1 passwd -l 1>/dev/null

  echo "6.2.2 Ensure no legacy \"+\" entries exist in /etc/passwd (Scored)"
  sed -i 's/^\+//g' /etc/passwd

  echo "6.2.3 Ensure no legacy \"+\" entries exist in /etc/shadow (Scored)"
  sed -i 's/^\+//g' /etc/shadow

  echo "6.2.4 Ensure no legacy \"+\" entries exist in /etc/group (Scored)"
  sed -i 's/^\+//g' /etc/group

  echo "6.2.5 Ensure root is the only UID 0 account (Scored)"

  cat /etc/passwd | awk -F: '($3 == 0) {print $1}' | while read user; do
    if [ "$user" != 'root' ]; then
      uid_number=$(_return_last_free_uid)

      if [ $uid_number -gt 0 ]; then
        echo -e "\t[!!] Changing login \"$user\" UID number 0 to $uid_number ..."

        passwd_new_line="$(grep "$user:" /etc/passwd|cut -f4- -d':')"
        passwd_new_line="$(echo -n "$user:x:$uid_number:$passwd_new_line")"
        sed -i "/^$user:/d" /etc/passwd
        echo "$passwd_new_line" >> /etc/passwd
      else
        echo -e "\t[!!] No FREE UID number found! This item cannot be able to continue...\n"
        break
      fi
    fi
  done

  # TODO: 6.2.6 Ensure root PATH Integrity (Scored)

  echo "6.2.7 Ensure all users' home directories exist (Scored)"
  echo "6.2.8 Ensure users' home directories permissions are 750 or more restrictive (Scored)"
  echo "6.2.9 Ensure users own their home directories (Scored)"
  echo "6.2.10 Ensure users' dot files are not group or world writable (Scored)"
  echo "6.2.11 Ensure no users have .forward files (Scored)"
  echo "6.2.12 Ensure no users have .netrc files (Scored)"
  echo "6.2.14 Ensure no users have .rhosts files (Scored)"

  cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | \
    awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false" && $7 != "/dev/null") { print $1 " " $6 }' | while read user dir; do

    if [ ! -d "$dir" ]; then
      mkdir -p "$dir"
    else
      ls -1 $dir/.[A-Za-z0-9]* | grep $dir | while read dot_file; do
        test -f "$dot_file" && chmod 0600 "$dot_file"
      done

      # TODO: Backup
      test -f "$dir/.forward" && rm -f "$dir/.forward"
      test -f "$dir/.netrc" && rm -f "$dir/.netrc"
      test -f "$dir/.rhosts" && rm -f "$dir/.rhosts"
    fi

    setfacl -b "$dir"
    chmod 0700 "$dir"
    chown "$user:" "$dir"
  done

  echo "6.2.15 Ensure all groups in /etc/passwd exist in /etc/group (Scored)"
  echo "6.2.16 Ensure no duplicate UIDs exist (Scored)"
  echo "6.2.18 Ensure no duplicate user names exist (Scored)"
  
  cat /etc/passwd | while read passwd_line; do
    passwd_login="$(echo -n "$passwd_line" | cut -f1 -d':')"
    passwd_uid="$(echo -n "$passwd_line" | cut -f3 -d':')"
    passwd_gid="$(echo -n "$passwd_line" | cut -f4 -d':')"

    # Ensure all groups in /etc/passwd exist in /etc/group
    group_gid_count=$(cat /etc/group | grep ":$passwd_gid:" | wc -l)

    if [ $group_gid_count -eq 0 ]; then
      echo -e "\t[!!] The GID \"$passwd_gid\" does not have entry in /etc/group."
    elif [ $group_gid_count -gt 1 ]; then
      echo -e "\t[!!] The GID \"$passwd_gid\" have duplicate entries in /etc/group."
    fi

    # Count UID
    passwd_uid_count=$(cat /etc/passwd | cut -f3 -d':' | sed -e 's/.*/:&:/' | grep ":$passwd_gid:" | wc -l)

    if [ $passwd_uid_count -gt 1 ]; then
      echo -e "\t[!!] The UID number \"$passwd_uid\" have duplicate entries in /etc/passwd."
    fi

    # Count usernames
    usernames_count=$(cat /etc/passwd | cut -f1 -d':' | grep "^$passwd_login$" | wc -l)

    if [ $usernames_count -gt 1 ]; then
      echo -e "\t[!!] The username \"$passwd_login\" have duplicate entries in /etc/passwd."
    fi
  done

  echo "6.2.17 Ensure no duplicate GIDs exist (Scored)"
  echo "6.2.19 Ensure no duplicate group names exist (Scored)"

  cat /etc/group | while read group_line; do
    group_name="$(echo -n "$group_line" | cut -f1 -d':')"
    group_gid="$(echo -n "$group_line" | cut -f3 -d':')"
    
    # Count GID
    group_gid_count=$(cat /etc/group | cut -f3 -d':' | sed -e 's/.*/:&:/' | grep ":$group_gid:" | wc -l)
    
    if [ $group_gid_count -gt 1 ]; then 
      echo -e "\t[!!] The GID number \"$group_gid\" have duplicate entries in /etc/group."
    fi

    # Count group names
    groupnames_count=$(cat /etc/group | cut -f1 -d':' | grep "^$group_name$" | wc -l)
    
    if [ $groupnames_count -gt 1 ]; then
      echo -e "\t[!!] The group name \"$group_name\" have duplicate entries in /etc/group."
    fi
  done

  echo "6.2.20 Ensure shadow group is empty (Scored)"
  
  if [ ! -z "$(grep "^shadow:" /etc/group)" ]; then
    shadow_gid="$(grep "^shadow:" /etc/group | cut -f3 -d':')"
    sed -i "/^shadow:/c\shadow:x:$shadow_gid:" /etc/group
  fi

  if [ ! -z "$(grep "^shadow:" /etc/gshadow)" ]; then
    sed -i '/^shadow:/c\shadow:!::' /etc/gshadow
  fi
}

function fix_permissions() {
  #
  # 1.1.25 Ensure sticky bit is set on all world-writable directories (Scored) 
  # 1.4.1 Ensure permissions on bootloader config are configured (Scored) 
  # 6.1.2 Ensure permissions on /etc/passwd are configured (Scored) 
  # 6.1.3 Ensure permissions on /etc/shadow are configured (Scored) 
  # 6.1.4 Ensure permissions on /etc/group are configured (Scored) 
  # 6.1.5 Ensure permissions on /etc/gshadow are configured (Scored) 
  # 6.1.6 Ensure permissions on /etc/passwd- are configured (Scored) 
  # 6.1.7 Ensure permissions on /etc/shadow- are configured (Scored)
  # 6.1.8 Ensure permissions on /etc/group- are configured (Scored) 
  #
  local perm_items_list=(
    '/boot/grub/grub.conf;root:root;0600' '/boot/grub2/grub.conf;root:root;0600'
    '/etc/grub2.cfg;root:root;0600' '/boot/grub2/user.cfg;root:root;0600'
    '/etc/grub.conf;root:root;0600' '/boot/grub/menu.lst;root:root;0600'
    '/etc/sysconfig/init;root:root;0600' '/etc/fstab;root:root;0644'
    '/etc/security/limits.conf;root:root;0644' '/etc/sysctl.conf;root:root;0600'
    '/etc/issue;root:root;0444' '/etc/issue.net;root:root;0444'
    '/etc/motd;root:root;0444' '/etc/postfix/main.cf;root:root;0640'
    '/etc/hosts.allow;root:root;0644' '/etc/hosts.deny;root:root;0644'
    '/etc/crontab;root:root;0600' '/etc/cron.hourly;root:root;0700'
    '/etc/cron.daily;root:root;0700' '/etc/cron.weekly;root:root;0700'
    '/etc/cron.monthly;root:root;0700' '/etc/cron.d;root:root;0700'
    '/root;root:root;0700' '/etc/ssh/sshd_config;root:root;0600'
    '/bin/gcc;root:root;0500' '/bin/g++;root:root;0500' '/usr/bin/gcc;root:root;0500'
    '/usr/bin/g++;root:root;0500' '/etc/security/opasswd;root:root;0600' '/etc/securetty;root:root;0400'
    '/etc/passwd;root:root;0644' '/etc/shadow;root:root;0000' '/etc/group;root:root;0644'
    '/etc/gshadow;root:root;0000' '/etc/passwd-;root:root;0644' '/etc/shadow-;root:root;0000'
    '/etc/group-;root:root;0644' '/etc/gshadow-;root:root;0000' '/etc/shells;root:root;0644'
    '/etc/login.defs;root:root;0400' '/var/spool/cron;root:root;0700' '/var/lib/aide;root:root;0700'
  )

  # Fix /etc, /var
  chmod -R o-w /etc && chown root:root /etc && chmod 0755 /etc
  chown root:root /var && chmod 0755 /var 

  echo "1.1.25 Ensure sticky bit is set on all world-writable directories (Scored)"

  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' \
    find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs --no-run-if-empty -n 1 chmod a+t

  local file_or_dir=''
  local owners=''
  local perm=''
  local i=0

  while [ $i -lt ${#perm_items_list[*]} ]; do
    file_or_dir="$(echo -n "${perm_items_list[$i]}" | cut -f1 -d';')"
    owners="$(echo -n "${perm_items_list[$i]}" | cut -f2 -d';')"
    perm="$(echo -n "${perm_items_list[$i]}" | cut -f3 -d';')"

    if [ -f "$file_or_dir" -o -d "$file_ir_dir" ]; then
      setfacl -b "$file_or_dir"
      chown "$owners" "$file_or_dir"
      chmod "$perm" "$file_or_dir"
    fi

    let i+=1
  done

  echo "4.2.4 Ensure permissions on all logfiles are configured (Scored)"
  setfacl -R -b /var/log
  chmod -R g-wx,o-rwx /var/log

  echo "6.1.10 Ensure no world writable files exist (Scored)"
  echo "6.1.11 Ensure no unowned files or directories exist (Scored)"
  echo "6.1.12 Ensure no ungrouped files or directories exist (Scored)"

  df --local | grep "^/" | awk '{print $6}' | while read partiton; do
    find "$partiton" -xdev -type f -perm -0002 | xargs --no-run-if-empty -n 1 chmod o-w
    find "$partiton" -xdev -nouser -o -nogroup | xargs --no-run-if-empty -n 1 chown root:root
  done

  echo "6.1.13 Audit SUID executables (Not Scored)"
  echo "6.1.14 Audit SGID executables (Not Scored)"

  local file_path=''

  local suid_sgid_files=('at' 'chsh' 'newgrp' 'chage' 'pkexec' 'unix_chkpwd' 'mount' 
    'mount.nfs' 'umount' 'gpasswd' 'Xorg' 'fusermount' 'write' 'screen' 'wall' 'locate')

  i=0
  while [ $i -lt ${#suid_sgid_files[*]} ]; do
    file_path="$(which "${suid_sgid_files[$i]}" 2>/dev/null)"

    if [ ! -z "$file_path" ]; then
      setfacl -b "$file_path"
      chmod u-s,g-s "$file_path"
    fi

    let i+=1
  done
}

function hardening_ntp() {
  #
  # 2.2.1.2 Ensure ntp is configured (Scored) 
  #
  # https://ntp.br/guia-linux-avancado.php
  #
  cat <<EOT >/etc/ntp.conf
# "memoria" para o escorregamento de frequencia do micro
# pode ser necessario criar esse arquivo manualmente com
# o comando touch ntp.drift
driftfile /etc/ntp.drift

# estatisticas do ntp que permitem verificar o histórico
# de funcionamento e gerar graficos
statsdir /var/log/ntpstats/
statistics loopstats peerstats clockstats
filegen loopstats file loopstats type day enable
filegen peerstats file peerstats type day enable
filegen clockstats file clockstats type day enable

# servidores publicos do projeto ntp.br
server a.st1.ntp.br iburst
server b.st1.ntp.br iburst
server c.st1.ntp.br iburst
server d.st1.ntp.br iburst
server gps.ntp.br iburst
server a.ntp.br iburst
server b.ntp.br iburst
server c.ntp.br iburst

# outros servidores
# server outro-servidor.dominio.br iburst

# configuracoes de restricao de acesso
restrict default kod notrap nomodify nopeer noquery
restrict -6 default kod notrap nomodify nopeer noquery

# desabilitar comando monlist
disable monitor
EOT

  echo "2.2.1.2 Ensure ntp is configured (Scored)"
  _install_package "ntp"

  touch /etc/ntp.drift

  ls -1 /etc/sysconfig/ntpd /etc/sysconfig/ntp 2>/dev/null | while read config_file; do
    if [ -f $config_file ]; then
      opts=$(cat "$config_file" | grep "^OPTIONS=" | cut -f2- -d'"')
      
      if [ -z "$(echo -n "$opts" | grep "\-u ntp:ntp")" ]; then
        echo "OPTIONS=\"$(echo -n "$opts"| cut -f1 -d'"')"\" >$config_file
      fi
    else
      echo 'OPTIONS="-u ntp:ntp"' >$config_file
    fi
  done

  # TODO: /etc/init.d/ntp
  # RUNASUSER=ntp

  _enable_service ntpd
}

function hardening_chrony() {
  #
  # 2.2.1.3 Ensure chrony is configured (Scored) 
  #
  cat <<EOT >/etc/chrony.conf
server a.st1.ntp.br iburst
server b.st1.ntp.br iburst
server c.st1.ntp.br iburst
server d.st1.ntp.br iburst
server gps.ntp.br iburst
server a.ntp.br iburst
server b.ntp.br iburst
server c.ntp.br iburst

driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
allow 127.0.0.1/32
logdir /var/log/chrony
log measurements statistics tracking
EOT

  echo "2.2.1.3 Ensure chrony is configured (Scored)"
  _install_package "chrony" 
  _enable_service chronyd
}

function hardening_selinux() {
  #
  # SELinux
  #
  echo "1.6.3 Ensure SELinux or AppArmor are installed (Not Scored)"
  _install_package "libselinux"
  _install_package "libselinux1"

  echo "1.6.1.2 Ensure the SELinux state is enforcing (Scored)"

  if [ -z "$(grep "^SELINUX=" /etc/selinux/config)" ]; then
    echo 'SELINUX=enforcing' >>/etc/selinux/config
  else
    sed -i '/^SELINUX=/c\SELINUX=enforcing' /etc/selinux/config
  fi

  echo "1.6.1.3 Ensure SELinux policy is configured (Scored)"

  if [ -z "$(grep "^SELINUXTYPE=" /etc/selinux/config)" ]; then
    echo 'SELINUXTYPE=targeted' >>/etc/selinux/config
  else
    sed -i '/^SELINUXTYPE=/c\SELINUXTYPE=targeted' /etc/selinux/config
  fi

  # TODO: 1.6.1.6 Ensure no unconfined daemons exist (Scored)

  echo "1.6.1.4 Ensure SETroubleshoot is not installed (Scored)"
  _uninstall_package "setroubleshoot"

  echo "1.6.1.4 Ensure SETroubleshoot is not installed (Scored)"
  _uninstall_package "mcstrans"
}

function hardening_aide() {
  #
  # AIDE - Advanced Intrusion Detection Environment
  # http://aide.sourceforge.net/stable/manual.html
  #
  local aide_path="$(which aide 2>/dev/null)"

  if [ -f "$aide_path" ]; then
    echo " [!!] Running aide. Be patient..."
    $aide_path --init
   
    if [ -z "$(crontab -u root -l | grep aide)" ]; then
      if [ -z "$(grep aide /etc/crontab)" ]; then
        echo "0 5 * * * $aide_path --check" >>/var/spool/cron/root
      fi
    fi
  else
    echo " [!!] AIDE not found! Skiping ..."
  fi
}

function hardening_rsyslog() {
  #
  # 4.2.1.2 Ensure logging is configured (Not Scored)  
  #
  echo "4.2.1.2 Ensure logging is configured (Not Scored)"
  echo "4.2.1.3 Ensure rsyslog default file permissions configured (Scored)"

  # TODO: 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host (Scored) 

  ls -1 /etc/rsyslog.d/* | while read f; do
    sed -i -e 's/^/##/' "$f"
  done  
  
  cat <<EOT >/etc/rsyslog.conf

\$umask 0000
\$FileCreateMode 0640
\$ModLoad imuxsock # provides support for local system logging (e.g. via logger command)
\$ModLoad imjournal # provides access to the systemd journal

*.emerg                                  :omusrmsg:* 
mail.*                                  -/var/log/mail 
mail.info                               -/var/log/mail.info 
mail.warning                            -/var/log/mail.warn 
mail.err                                 /var/log/mail.err 
news.crit                               -/var/log/news/news.crit 
news.err                                -/var/log/news/news.err 
news.notice                             -/var/log/news/news.notice 
*.=warning;*.=err                       -/var/log/warn 
*.crit                                   /var/log/warn 
*.*;mail.none;news.none                 -/var/log/messages 
local0.*				-/var/log/sudo.log
local1.*				-/var/log/sshd.log
local2,local3.*                         -/var/log/localmessages 
local4,local5.*                         -/var/log/localmessages 
local6,local7.*                         -/var/log/localmessages 
EOT
 
 pkill -HUP rsyslogd
}

function hardening_sshd() {
  #
  # 5.2 SSH Server Configuration 
  #
  local security_item_list=(
    '5.2.2 Ensure SSH Protocol is set to 2 (Scored):Protocol 2'
    '5.2.3 Ensure SSH LogLevel is set to INFO (Scored):LogLevel INFO;SyslogFacility LOCAL1'
    '5.2.4 Ensure SSH X11 forwarding is disabled (Scored):X11Forwarding no'
    '5.2.5 Ensure SSH MaxAuthTries is set to 4 or less (Scored)MaxAuthTries 3'
    '5.2.6 Ensure SSH IgnoreRhosts is enabled (Scored):IgnoreRhosts yes'
    '5.2.7 Ensure SSH HostbasedAuthentication is disabled (Scored):HostbasedAuthentication no'
    '5.2.8 Ensure SSH root login is disabled (Scored):PermitRootLogin no'
    '5.2.9 Ensure SSH PermitEmptyPasswords is disabled (Scored):PermitEmptyPasswords no'
    '5.2.10 Ensure SSH PermitUserEnvironment is disabled (Scored):PermitUserEnvironment no'
    '5.2.11 Ensure only approved MAC algorithms are used (Scored):MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com,curve25519sha256@libssh.org,diffie-hellman-group-exchange-sha256'
    '5.2.12 Ensure SSH Idle Timeout Interval is configured (Scored):ClientAliveInterval 900;ClientAliveCountMax 0'
    '5.2.13 Ensure SSH LoginGraceTime is set to one minute or less (Scored):LoginGraceTime 120'
    '5.2.15 Ensure SSH warning banner is configured (Scored):Banner /etc/issue.net'
  ) 

  local deny_user_list=('root' 'bin' 'daemon' 'adm' 'lp' 'sync' 'shutdown' 'halt' 'mail' 'operator'
   'games' 'ftp' 'nobody' 'uucp' 'news' 'xfs' 'gdm' 'rpcuser' 'rpc' 'named' 'mailnull' 'postgres'
   'piranha' 'httpd' 'apache' 'pvm' 'squid' 'lpd' 'abrt' 'chrony' 'nfsnobody' 'avahi' 'sshd'
   'postfix' 'ntp' 'tcpdump' 'jboss' 'nscd' 'nslcd' 'mysql' 'gnome-initial-setup')

  local i=0
  local title=''
  local param_value=''
  local param=''

  while [ $i -lt ${#security_item_list[*]} ]; do
    title="$(echo -n "${security_item_list[$i]}" | cut -f1 -d ':')"
    param_value="$(echo -n "${security_item_list[$i]}" | cut -f2 -d ':')"
    param="$(echo -n "$param_value" | awk '{print $1}')"

      echo "$param_value" | tr ';' '\n' | while read p; do
        param="$(echo -n "$p" | awk '{print $1}')"
        sed -i "/^\(#\+\)\?$param/c\\$p" /etc/ssh/sshd_config     
      done

    let i+=1
  done

  echo "5.2.14 Ensure SSH access is limited (Scored)"

  sed -i '/^\(#\+\)\?AllowUsers\|AllowGroups\|DenyUsers\|DenyGroups/d' /etc/ssh/sshd_config
  echo "DenyUsers ${deny_user_list[*]}" >> /etc/ssh/sshd_config

  _restart_service sshd
}

function hardening_pam() {
  # 
  # 5.3 Configure PAM 
  #
  local pwquality_items=('minlen = 8' 'dcredit = -2' 'ucredit = -1' 'ocredit = -1' 'lcredit = -2')

  local pam_lib_dir=('/usr/lib/security' '/usr/lib64/security')

  echo "5.3.1 Ensure password creation requirements are configured (Scored)"

  grep -H 'pam_cracklib.so' /etc/pam.*/* | cut -f1 -d':'| while read pam_file; do
    if [ -f "$pam_file" -a ! -L "$pam_file" ]; then
      sed -i 's/pam_cracklib.so/password requisite pam_cracklib.so try_first_pass retry=3 minlen=8 lcredit=-2 dcredit=-2 ucredit=-1 ocredit=-1 difok=3 maxrepeat=2/g' "$pam_file"
    fi
  done

  local i=0  
  local param=''

  if [ -f /etc/security/pwquality.conf ]; then
  
    while [ $i -lt ${#pwquality_items[*]} ]; do
      param="$(echo -n "${pwquality_items[$i]}" | cut -f1 -d'=' | tr -d ' ')"

      if [ -z "$(grep "^$param" /etc/security/pwquality.conf)" ]; then
        echo "${pwquality_items[$i]}" >> /etc/security/pwquality.conf
      else
        sed -i "/^\(\#\+\?\ \?\+\)\?$param/c\\${pwquality_items[$i]}" /etc/security/pwquality.conf
      fi

      let i+=1
    done
  
  fi

  echo "5.3.2 Ensure lockout for failed password attempts is configured (Not Scored)"
  echo "5.3.3 Ensure password reuse is limited (Not Scored)"
  echo "5.3.4 Ensure password hashing algorithm is SHA-512 (Not Scored)"

  ls -1 /etc/pam.d/system-auth /etc/pam.d/password-auth | while read pam_file; do
    pam_env_line_num=$(grep -n pam_env.so "$pam_file" | head -1 | tail -1 | cut -f1 -d':')
    
    if [ ! -z "$pam_env_line_num" ]; then
      let pam_env_line_num+=1
      if [ -z "$(cat "$pam_file" | head -$pam_env_line_num | tail -1 | grep " pam_faillock.so ")" ]; then
        sed -i "$pam_env_line_num i auth required pam_faillock.so preauth silent audit deny=6" "$pam_file"
      fi
       
      pam_unix_line_num=$(grep -n "^auth" "$pam_file" | grep pam_unix.so | head -1 | tail -1 | cut -f1 -d':')
      let pam_unix_line_num+=1
      if [ -z "$(cat "$pam_file" | head -$pam_unix_line_num | tail -1 | grep  " pam_faillock.so ")" ]; then    
        sed -i "$pam_unix_line_num i auth [default=die] pam_faillock.so authfail audit deny=6" "$pam_file"
      fi
     
      pam_permit_line_num=$(grep -n pam_permit.so "$pam_file" | grep ":account" | cut -f1 -d':')
      let pam_permit_line_num+=1
      if [ -z "$(cat "$pam_file" | head -$pam_permit_line_num | tail -1 | grep "pam_faillock.so$")" ]; then
        sed -i "$pam_permit_line_num i account required pam_faillock.so" "$pam_file"
      fi

      # TODO: pam_pwhistory.so
      if [ -z "$(cat "$pam_file" | grep " pam_unix.so " | grep 'remember=6')" ]; then
        sed -i -E 's/^(password\s+sufficient\s+pam_unix.so.*)/\1 remember=6/' "$pam_file"
      fi
      
      if [ -z "$(egrep "^password\s+sufficient\s+pam_unix.so\s+sha512" "$pam_file")" ]; then
        sed -i -E 's/^(password\s+sufficient\s+pam_unix.so.*)/\1 sha512/' "$pam_file"
        sed -i '/^ENCRYPT_METHOD/c\ENCRYPT_METHOD SHA512' /etc/login.defs
      fi
    else
      break
    fi
  done
}

function hardening_accounts_env() {
  #
  # 5.4 User Accounts and Environment 
  #
  local security_item_list=(
    '5.4.1.1 Ensure password expiration is 365 days or less (Scored):PASS_MAX_DAYS 90:chage --maxdays 90'
    '5.4.1.2 Ensure minimum days between password changes is 7 or more (Scored):PASS_MIN_DAYS 7:chage --mindays 7'
    '5.4.1.3 Ensure password expiration warning days is 7 or more (Scored):PASS_WARN_AGE 7:chage --warndays 7'
    '5.4.1.X Ensure minimum password length is 8 characters or more (Scored):PASS_MIN_LEN 8:'
  )

  local uid_min="$(_return_uid_min_value)"

  local i=0
  local title=''
  local new_key_value=''
  local key=''
  local shell_cmd=''
  local user=''

  while [ $i -lt ${#security_item_list[*]} ]; do
    title="$(echo -n "${security_item_list[$i]}" | cut -f1 -d':')"
    new_key_value="$(echo -n "${security_item_list[$i]}" | cut -f2 -d':')"
    key="$(echo -n "$new_key_value" | awk '{print $1}')"
    shell_cmd="$(echo -n "${security_item_list[$i]}" | cut -f3 -d':')"

    if [ -z "$(grep "^$key" /etc/login.defs)" ]; then
      echo "$new_key_value" >>/etc/login.defs
    else
      sed -i "/^$key/c\\$new_key_value" /etc/login.defs   
    fi

    # Apply password policy to existing users.
    if [ "$key" != 'PASS_MIN_LEN' ]; then
      for user in $(awk -v min_uid_value="$uid_min" -F: '($3 >= min_uid_value) {print $1}' /etc/passwd) ; do
        if [ $user != "root" ]; then
          $($shell_cmd $user)
        fi
      done
    fi

    let i+=1
  done

  echo "5.4.1.4 Ensure inactive password lock is 30 days or less (Scored)"
  useradd -D -f 30

  for user in $(awk -v min_uid_value="$uid_min" -F: '($3 >= min_uid_value) {print $1}' /etc/passwd) ; do
    chage --inactive 30 $user
    # TODO: 5.4.1.5 Ensure all users last password change date is in the past (Scored)
  done

  echo "5.4.2 Ensure system accounts are non-login (Scored)"

  for user in $(awk -v min_uid_value="$uid_min" -F: '($3 < min_uid_value) {print $1}' /etc/passwd) ; do 
    if [ $user != "root" ]; then 
      usermod -s /dev/null $user &>/dev/null
    fi
  done
  
  # Adjusting /etc/shells
  test -z "$(grep "^/dev/null$" /etc/shells)" && echo '/dev/null' >>/etc/shells
  
  echo "5.4.3 Ensure default group for the root account is GID 0 (Scored)"
  usermod -g 0 root &>/dev/null

  echo "5.4.4 Ensure default user umask is 027 or more restrictive (Scored)"
 
  sed -i '/^UMASK/c\UMASK 027' /etc/login.defs
 
  echo "5.4.5 Ensure default user shell timeout is 900 seconds or less (Scored)"

  ls -1 /etc/bashrc /etc/profile | while read conf_file; do
    sed -i -E '/umask\s+/c\umask 027' "$conf_file"

    if [ -z "$(grep "TMOUT" "$conf_file")" ]; then
      echo 'export TMOUT=600' >>"$conf_file"
    else
      sed -i -E '/\s+TMOUT/c\export TMOUT=600' "$conf_file"
    fi

    if [ -z "$(grep "TIMEOUT" "$conf_file")" ]; then
      echo 'export TIMEOUT=600' >>"$conf_file"
    else
      sed -i -E '/\s+TIMEOUT/c\export TIMEOUT=600' "$conf_file"
    fi

  done

  echo "5.6 Ensure access to the su command is restricted (Scored)"
  chown root:wheel /bin/su 
  chmod 4550 /bin/su
}

function hardening_boot_loader() {
  #
  # 1.4 Secure Boot Settings 
  #
  local rand_passwd=''
  local crypt_passwd=''
  local plain_passwd=''

  local boot_add_items=(
    '3.3.3 Ensure IPv6 is disabled (Not Scored):ipv6.disable=1'
    '4.1.3 Ensure auditing for processes that start prior to auditd is enabled (Scored):audit=1'
  )

  local boot_remove_items=(
    '1.6.1.1 Ensure SELinux is not disabled in bootloader configuration (Scored):enforcing=0,selinux=0'
    '1.6.2.1 Ensure AppArmor is not disabled in bootloader configuration (Scored):apparmor=0'
  )

  echo "1.4.2 Ensure bootloader password is set (Scored)"

  mount -o remount,rw /boot &>/dev/null

  if [ $REBOOT_PASSWORD -eq 1 ]; then

    if [ ! -z "$(which grub2-setpassword 2>/dev/null)" ]; then
      # For grub2 based systems 
      # https://www.thegeekdiary.com/centos-rhel-7-how-to-password-protect-grub2-menu-entries/
      sed -i "/^CLASS=/s/ --unrestricted//" /etc/grub.d/10_linux

      echo -e " [!!] Could not generate a random password! Type a secure password:\n"
      grub-mkpasswd-pbkdf2 2>/dev/null || grub2-setpassword 2>/dev/null
      grub2-mkconfig -o /boot/grub2/grub.cfg
    elif [ ! -z "$(which grub-md5-crypt 2>/dev/null)" ]; then
      # For grub based systems 
      rand_passwd="$(_generate_random_password)"
    
      if [ ! -z "$rand_passwd" ]; then
        plain_passwd="$(echo -n "$rand_passwd" | cut -f1 -d':')"
        crypt_passwd="$(echo -n "$rand_passwd" | cut -f2 -d':')"

        if [ -f "/boot/grub/menu.lst" ]; then
          echo -e " [!!] GRUB Auto-generated Password (** KEEP IT SAFE **) : $plain_passwd\n"
        
          if [ -z "$(grep "^password" /boot/grub/menu.lst)" ]; then
            # Grub password not set
            sed -i "1s/^/password --md5 $crypt_passwd\n/" /boot/grub/menu.lst
          else
            # Grub password set
            sed -i "/^password/c\password --md5 $crypt_passwd" /boot/grub/menu.lst
          fi
        else
          echo -e " [!!] File \"/boot/grub/menu.lst\" not found!\n"
        fi
      else
        echo -e " [!!] Could not generate a random password! Type a secure password:\n"
        grub-md5-crypt 
        echo -e " [!!] Copy and paste the encrypted password into the global section of \"/boot/grub/menu.lst\".\n"
        echo -e "\t password --md5 <encrypted-password> \n\n"
      fi
    fi

  else
    echo " [!!] Skiping ..."
  fi

  echo "1.4.3 Ensure authentication required for single user mode (Not Scored)"
  echo "1.4.4 Ensure interactive boot is not enabled (Not Scored)"

  if [ -f /etc/sysconfig/init ]; then
    if [ -z "$(grep "^SINGLE=/sbin/sulogin$" /etc/sysconfig/init)" ]; then
      echo 'SINGLE=/sbin/sulogin' >> /etc/sysconfig/init
    fi
  
    if [ -z "$(grep "^PROMPT=" /etc/sysconfig/init)" ]; then
      sed -i '/^PROMPT=/c\PROMPT=yes' /etc/sysconfig/init
    else
      echo 'PROMPT=yes' >> /etc/sysconfig/init
    fi
  else
    echo -e " [!!] File \"/etc/sysconfig/init\" not found!\n"
  fi

  if [ -f /etc/sysconfig/boot ]; then
    if [ -z "$(grep "^PROMPT_FOR_CONFIRM=" /etc/sysconfig/boot)" ]; then
      echo 'PROMPT_FOR_CONFIRM="no"' >> /etc/sysconfig/boot
    else
      sed -i '/PROMPT_FOR_CONFIRM=/c\PROMPT_FOR_CONFIRM="no"' /etc/sysconfig/boot
    fi
  else
    echo -e " [!!] File \"/etc/sysconfig/boot\" not found!\n"
  fi

  local i=0
  local title=''
  local grub_param=''

  # Remove bootloader options
  while [ $i -lt ${#boot_remove_items[*]} ]; do
    title="$(echo -n "${boot_remove_items[$i]}" | cut -f1 -d':')"
    grub_item="$(echo -n "${boot_remove_items[$i]}" | cut -f2 -d':')"

    if [ -f /etc/default/grub ]; then
      grub_params="$(cat /etc/default/grub | grep "^GRUB_CMDLINE_LINUX=" | cut -f2 -d'"')"

      # SELinux
      if [ "$grub_item" == 'enforcing=0,selinux=0' ]; then
        grub_params="$(echo -n '"' ; echo -n "$grub_params" | sed -e 's/selinux=0//g' -e 's/enforcing=0//g')"
        sed -i "/^GRUB_CMDLINE_LINUX=/c\GRUB_CMDLINE_LINUX=$grub_params\"" /etc/default/grub
      else  
        grub_params="$(echo -n "$grub_params" | sed -e "s/$grub_item//g")"
        sed -i "/^GRUB_CMDLINE_LINUX=/c\GRUB_CMDLINE_LINUX=\"$grub_params\"" /etc/default/grub
      fi
    else 
      echo " [!!] Bootloader not supported!"
      break
    fi

    let i+=1
  done

  # Add bootloader options
  i=0
  while [ $i -lt ${#boot_add_items[*]} ]; do
    title="$(echo -n "${boot_add_items[$i]}" | cut -f1 -d':')"
    grub_item="$(echo -n "${boot_add_items[$i]}" | cut -f2 -d':')"

    if [ -f /etc/default/grub ]; then
      # For grub2 based systems
      grub_params="$(cat /etc/default/grub | grep "^GRUB_CMDLINE_LINUX=" | cut -f2 -d'"')"
    
      if [ -z "$(echo -n "$grub_params" | grep "$grub_item")" ]; then
        grub_params="$(echo -n '"' ; echo -n "$grub_params" ; echo -n " $grub_item\"")"
        sed -i "/^GRUB_CMDLINE_LINUX=/c\GRUB_CMDLINE_LINUX=$grub_params" /etc/default/grub
      fi
    else
      echo " [!!] Bootloader not supported!"
      break
    fi
     
    let i+=1
  done
 
  echo -e " [!!] Update Kernel boot options ...\n"
    grub2-mkconfig -o /boot/grub2/grub.cfg || update-grub
    mount -o remount,ro /boot &>/dev/null
  echo -e "\n"
}

function sysctl_hardening() {
  #
  # 1.5 Additional Process Hardening
  # 3 Network Configuration 
  # 3.1 Network Parameters (Host Only) 
  # 3.2 Network Parameters (Host and Router) 
  # 3.3 IPv6 
  #
  local security_item_list=(
    '1.5.1 Ensure core dumps are restricted (Scored):fs.suid_dumpable=0' 
    '1.5.3 Ensure address space layout randomization (ASLR) is enabled (Scored):kernel.randomize_va_space=2' 
    '3.1.1 Ensure IP forwarding is disabled (Scored):net.ipv4.ip_forward=0'
    '3.1.2 Ensure packet redirect sending is disabled (Scored):net.ipv4.conf.all.send_redirects=0,net.ipv4.conf.default.send_redirects=0'
    '3.2.1 Ensure source routed packets are not accepted (Scored):net.ipv4.conf.all.accept_source_route=0,net.ipv4.conf.default.accept_source_route=0'
    '3.2.2 Ensure ICMP redirects are not accepted (Scored):net.ipv4.conf.all.accept_redirects=0,net.ipv4.conf.default.accept_redirects=0'
    '3.2.3 Ensure secure ICMP redirects are not accepted (Scored):net.ipv4.conf.all.secure_redirects=0,net.ipv4.conf.default.secure_redirects=0'
    '3.2.4 Ensure suspicious packets are logged (Scored):net.ipv4.conf.all.log_martians=1,net.ipv4.conf.default.log_martians=1'
    '3.2.5 Ensure broadcast ICMP requests are ignored (Scored):net.ipv4.icmp_echo_ignore_broadcasts=1'
    '3.2.6 Ensure bogus ICMP responses are ignored (Scored):net.ipv4.icmp_ignore_bogus_error_responses=1'
    '3.2.7 Ensure Reverse Path Filtering is enabled (Scored):net.ipv4.conf.all.rp_filter=1,net.ipv4.conf.default.rp_filter=1'
    '3.2.8 Ensure TCP SYN Cookies is enabled (Scored):net.ipv4.tcp_syncookies=1' 
    '3.3.1 Ensure IPv6 router advertisements are not accepted (Not Scored):net.ipv6.conf.all.accept_ra=0,net.ipv6.conf.default.accept_ra=0'
    '3.3.2 Ensure IPv6 redirects are not accepted (Not Scored):net.ipv6.conf.all.accept_redirects=0,net.ipv6.conf.default.accept_redirects=0'
  )

  local title=''
  local sysctl_values=''
  local param=''
  local i=0

  while [ $i -lt ${#security_item_list[*]} ]; do
    title="$(echo -n "${security_item_list[$i]}" | cut -f1 -d':')"
    sysctl_values="$(echo -n "${security_item_list[$i]}" | cut -f2 -d':')"

    ls -1 /etc/sysctl.conf /etc/sysctl.d/* | while read sysctl_config_file; do
      if [ -f "$sysctl_config_file" ]; then
    
        echo "$sysctl_values" | tr ',' '\n' | while read sysctl_param_value; do
           param="$(echo -n "$sysctl_param_value" | cut -f1 -d '=')"

           if [ -z "$(grep "^$param" "$sysctl_config_file")" ]; then
             echo "$sysctl_param_value" >>$sysctl_config_file
           else
             sed -i "/^$param/c\\$sysctl_param_value" "$sysctl_config_file"
           fi

           sysctl -q -w "$sysctl_param_value"
        done

      fi
    done

    let i+=1
  done

  sysctl -q -w net.ipv4.route.flush=1 
  sysctl -q -w net.ipv6.route.flush=1
}

function process_hardening() {
  #
  # 1.5 Additional Process Hardening 
  #
  echo "1.5.1 Ensure core dumps are restricted (Scored)"

  ls -1 /etc/security/limits.conf /etc/security/limits.d/* | while read limits_file; do
    if [ -f $limits_file ]; then
      if [ -z "$(grep "hard core" $limits_file)" ]; then
        echo '* hard core 0' >> $limits_file
      fi
    fi
  done

  echo "1.5.2 Ensure XD/NX support is enabled (Not Scored)"
  dmesg | grep " NX "

  echo -e "\n1.5.4 Ensure prelink is disabled (Scored)"

  # prelink is a program that modifies ELF shared libraries and ELF dynamically 
  # linked binaries in such a way that the time needed for the dynamic linker 
  # to perform relocations at startup significantly decreases.
  # The prelinking feature can interfere with the operation of AIDE, because it changes 
  # binaries. Prelinking can also increase the vulnerability of the system if a malicious 
  # user is able to compromise a common library such as libc. 

  _install_package "prelink"

  if [ ! -z "$(which prelink 2>/dev/null)" ]; then
    prelink -ua
  else
    echo " [!!] Prelink not found! Cannot run ..."
  fi

  _uninstall_package "prelink"
}

function hardening_apparmor() {
  #
  # 1.6.2 Configure AppArmor 
  # 1.6.2.2 Ensure all AppArmor Profiles are enforcing (Scored
  # 1.6.3 Ensure SELinux or AppArmor are installed (Not Scored) 
  #

  echo "1.6.3 Ensure SELinux or AppArmor are installed (Not Scored)"
  _install_package "apparmor"
}

function warning_banners() {
  #
  # 1.7 Warning Banners 
  #  
  echo "1.7.1 Command Line Warning Banners."
  echo "1.7.1.1 Ensure message of the day is configured properly (Scored)"

  local banner='
##***************************************************************************##
#                             NOTICE TO USERS                                 #
#                                                                             #
# This computer system is the private property of its owner, whether          #
# individual, corporate or government.  It is for authorized use only.        #
# Users (authorized or unauthorized) have no explicit or implicit             #
# expectation of privacy.                                                     #
#                                                                             #
# Any or all uses of this system and all files on this system may be          #
# intercepted, monitored, recorded, copied, audited, inspected, and           #
# disclosed to your employer, to authorized site, government, and law         #
# enforcement personnel, as well as authorized officials of government        #
# agencies, both domestic and foreign.                                        #
#                                                                             #
# By using this system, the user consents to such interception, monitoring,   #
# recording, copying, auditing, inspection, and disclosure at the             #
# discretion of such personnel or officials.  Unauthorized or improper use    #
# of this system may result in civil and criminal penalties and               #
# administrative or disciplinary action, as appropriate. By continuing to use #
# this system you indicate your awareness of and consent to these terms       #
# and conditions of use. LOG OFF IMMEDIATELY if you do not agree to the       #
# conditions stated in this warning.                                          #
#                                                                             #
##***************************************************************************##'
  
  echo "1.7.1.1 Ensure message of the day is configured properly (Scored)"
  cat /dev/null >/etc/motd

  echo "1.7.1.2 Ensure local login warning banner is configured properly (Not Scored)"
  echo "$banner" >/etc/issue

  echo "1.7.1.3 Ensure remote login warning banner is configured properly (Not Scored)"
  echo "$banner" >/etc/issue.net 

  echo "1.7.2 Ensure GDM login banner is configured (Scored)"

  if [ -f /etc/dconf/profile/gdm ]; then
    echo 'user-db:user' >/etc/dconf/profile/gdm
    echo 'system-db:gdm' >>/etc/dconf/profile/gdm
    echo 'file-db:/usr/share/gdm/greeter-dconf-defaults' >>/etc/dconf/profile/gdm

    echo '[org/gnome/login-screen]' >/etc/dconf/db/gdm.d/01-banner-message
    echo 'banner-message-enable=true' >>/etc/dconf/db/gdm.d/01-banner-message
    echo "banner-message-text='Authorized uses only. All activity may be monitored and reported.'" >>/etc/dconf/db/gdm.d/01-banner-message

    dconf update 1>/dev/null
  else 
    echo -e " [!!] GDM was not installed!\n"
  fi
}

function hardening_services() {
  #
  # 2 Services
  #
  local inetd_xinetd_items=(
    '2.1.1 Ensure chargen services are not enabled (Scored):chargen'
    '2.1.2 Ensure daytime services are not enabled (Scored):daytime'
    '2.1.3 Ensure discard services are not enabled (Scored):discard'
    '2.1.4 Ensure echo services are not enabled (Scored):echo'
    '2.1.5 Ensure time services are not enabled (Scored):time'
    '2.1.6 Ensure rsh server is not enabled (Scored):shell,login,exec,rsh,rlogin,rexec'
    '2.1.7 Ensure talk server is not enabled (Scored):talk,ntalk'
    '2.1.8 Ensure telnet server is not enabled (Scored):telnet'
    '2.1.9 Ensure tftp server is not enabled (Scored):tftp'
  )

  local disable_service_items=(
    '1.1.26 Disable Automounting (Scored):autofs'
    '2.1.10 Ensure xinetd is not enabled (Scored):xinetd'
    '2.2.3 Ensure Avahi Server is not enabled (Scored):avahi-daemon'
    '2.2.4 Ensure CUPS is not enabled (Scored):cups'
    '2.2.5 Ensure DHCP Server is not enabled (Scored):dhcpd'
    '2.2.6 Ensure LDAP server is not enabled (Scored):slapd'
    '2.2.7 Ensure NFS and RPC are not enabled (Scored):nfs,rpcbind'
    '2.2.8 Ensure DNS Server is not enabled (Scored):named'
    '2.2.9 Ensure FTP Server is not enabled (Scored):vsftpd'
    '2.2.10 Ensure HTTP server is not enabled (Scored):httpd'
    '2.2.11 Ensure IMAP and POP3 server is not enabled (Scored):dovecot'
    '2.2.12 Ensure Samba is not enabled (Scored):smb'
    '2.2.13 Ensure HTTP Proxy Server is not enabled (Scored):squid,proxy'
    '2.2.14 Ensure SNMP Server is not enabled (Scored):snmpd'    
    '2.2.16 Ensure rsync service is not enabled (Scored):rsyncd'
    '2.2.17 Ensure NIS Server is not enabled (Scored):ypserv'
  )

  local enable_service_items=(
    '4.1.2 Ensure auditd service is enabled (Scored):auditd'
    '4.2.1.1 Ensure rsyslog Service is enabled (Scored):rsyslog'
    '5.1.1 Ensure cron daemon is enabled (Scored):crond'
  )

  echo "2.1 inetd Services."
  echo "2.2 Special Purpose Services."

  local i=0
  local title=''
  local service=''

  # inetd/xinetd
  while [ $i -lt ${#inetd_xinetd_items[*]} ]; do
    title="$(echo -n "${inetd_xinetd_items[$i]}" | cut -f1 -d':')"
    service="$(echo -n "${inetd_xinetd_items[$i]}" | cut -f2 -d':')"
    
    echo "$title"
    _disable_inetd_xinetd_service "$service" 

    let i+=1
  done
    
  i=0
  while [ $i -lt ${#disable_service_items[*]} ]; do
    title="$(echo -n "${disable_service_items[$i]}" | cut -f1 -d':')"
    service="$(echo -n "${disable_service_items[$i]}" | cut -f2 -d':')"

    echo "$title"
    _disable_service "$service"

    let i+=1
  done 

  echo "2.2.2 Ensure X Window System is not installed (Scored)"
  _uninstall_package "xorg-x11*,xserver-xorg*"

  echo "2.2.15 Ensure mail transfer agent is configured for local-only mode (Scored)"
  hardening_mta
 
  i=0
  while [ $i -lt ${#enable_service_items[*]} ]; do
    title="$(echo -n "${enable_service_items[$i]}" | cut -f1 -d':')"
    service="$(echo -n "${enable_service_items[$i]}" | cut -f2 -d':')"

    echo "$title"
    _enable_service "$service"

    let i+=1
  done 
}

function hardening_service_clients() {
  #
  # 2.3 Service Clients
  #
  local security_item_list=(
    '2.3.1 Ensure NIS Client is not installed (Scored):ypbind'
    '2.3.2 Ensure rsh client is not installed (Scored):rsh,rcp,rlogin'
    '2.3.3 Ensure talk client is not installed (Scored):talk'
    '2.3.4 Ensure telnet client is not installed (Scored):telnet'
    '2.3.5 Ensure LDAP client is not installed (Scored):openldap-clients,openldap2-client,ldap-utils'
  )

  local i=0
  local title=''
  local client=''

  while [ $i -lt ${#security_item_list[*]} ]; do
    title="$(echo -n "${security_item_list[$i]}" | cut -f1 -d':')"
    client="$(echo -n "${security_item_list[$i]}" | cut -f2 -d':')"

    echo -n "$title "
    _uninstall_package "$client"

    let i+=1
  done
}

function service_clients() {
  #
  # 2.3 Service Clients 
  #
  local services_list=('2.3.1 Ensure NIS Client is not installed (Scored).:ypbind'
    '2.3.2 Ensure rsh client is not installed (Scored).:rsh'
    '2.3.3 Ensure talk client is not installed (Scored).:talk'
    '2.3.4 Ensure telnet client is not installed (Scored).:telnet'
    '2.3.5 Ensure LDAP client is not installed (Scored).:openldap-clients,openldap2-client,ldap-utils')
    
  local title=''
  local service=''
  local i=0

  while [ $i -lt ${#services_list[*]} ]; do
    title="$(echo -n "${services_list[$i]}" | cut -f1 -d':')"
    service="$(echo -n "${services_list[$i]}" | cut -f2 -d':')"
    
    echo "$title"

    read -p "[??] Type YES to uninstall \"$service\" : " result

    if [ "$result" == 'YES' ]; then
      yum -y remove "$(echo -n "$service" | tr -s ',' ' ')"
    fi

    let i+=1
  done
}

function baseline() {
  #
  # Start the baseline fix
  #
  set +o history

  echo "1 Initial Setup."
  echo "1.1 Filesystem Configuration."
  echo "1.1.1 Disable unused filesystems."
  echo "3 Network Configuration."
  echo -e "3.5 Uncommon Network Protocols\n"
  hardening_kernel_modules
  partition_hardening

  # Package manager must be one of the first.
  echo -e "\n1.2 Configure Software Updates.\n"
  hardening_package_manager  
  install_required_packages

  echo -e "\n1.4 Secure Boot Settings.\n"
  hardening_boot_loader

  echo "1.5 Additional Process Hardening."
  echo "3.1 Network Parameters (Host Only)"
  echo "3.2 Network Parameters (Host and Router)"
  echo -e "3.3 IPv6\n"
  sysctl_hardening
  process_hardening

  echo -e "\n1.6 Mandatory Access Control."
  echo "1.6.1 Configure SELinux"
  if [ $ENABLE_SELINUX == 1 ]; then
    hardening_selinux
  else
    echo " [!!] Skiping ..."
  fi

  echo -e "\n1.6.2 Configure AppArmor."
  hardening_apparmor

  echo -e "\n1.7 Warning Banners."
  warning_banners

  echo -e "\n2 Services."
  echo "2.1 inetd Services."
  hardening_services

  echo -e "\n2.2 Special Purpose Services."
  echo "2.2.1 Time Synchronization."
  echo "2.2.1.1 Ensure time synchronization is in use (Not Scored)"
  hardening_ntp
  hardening_chrony 

  echo -e "\n2.3 Service Clients."
  hardening_service_clients
 
  echo -e "\n3.6 Firewall Configuration."
  if [ $ENABLE_FIREWALL == 1 ]; then
    hardening_firewall
  else
    echo " [!!] Skiping ..."
  fi

  echo -e "\n4 Logging and Auditing."
  hardening_logging_auditing
  hardening_rsyslog

  echo -e "\n5 Access, Authentication and Authorization."
  hardening_at_cron

  echo -e "\n5.2 SSH Server Configuration."
  hardening_sshd

  echo -e "\n5.3 Configure PAM."
  hardening_pam

  echo -e "\n5.4 User Accounts and Environment"
  echo "5.4.1 Set Shadow Password Suite Parameters"
  hardening_accounts_env

  # TODO:
  # 3.7 Ensure wireless interfaces are disabled (Not Scored)   

  echo -e "\n6.1 System File Permissions."
  fix_permissions

  echo -e "\n6.2 User and Group Settings."
  hardening_user_group

  echo -e "\n1.3 Filesystem Integrity Checking."
  if [ $ENABLE_AIDE == 1 ]; then
    hardening_aide
  else
    echo " [!!] Skiping ..."
  fi

  echo -e "\n ... done!"

  set -o history
} 

function main() {
  #
  # main
  #
  splash_screen

  if [ "$(whoami)" != 'root' ]; then
    echo -e "\n[ERROR] You must be root to run this script ..."
    echo "Exiting ..."
    exit 1
  elif [ -z "$BACKUP_DIR" ]; then
    echo -e "\n[ERROR] You should specify a backup directory!"
    echo "Type ./$(basename "$0") -h to get help."
    echo "Exiting ..."
    exit 1
  elif [ -z "$ROOT_MAILTO" ]; then
    echo -e "\n[ERROR] You should specify a person who gets root's e-mail."
    echo "Type ./$(basename "$0") -h to get help."
    echo "Exiting ..."
    exit 1
  else
    echo -e "\n[!!] Start baseline fix ..."
    do_backup
    baseline
  fi
}

while test -n "$1"; do
  case "$1" in
     -h|--help)
          show_help          
          exit 0
          ;;
     -V|--version)
          echo "$SCRIPT_VERSION"
          exit 0
          ;;
     --enable-boot-password)
          REBOOT_PASSWORD=1
          ;;
     --enable-aide)
          ENABLE_AIDE=1
          ;;
     --root-mailto)
          shift
          ROOT_MAILTO="$1"
          ;;
     -b|--backup-dir)
          shift
          BACKUP_DIR="$1"
          ;;
     --enable-firewall)
          ENABLE_FIREWALL=1
          ;;
     --enable-selinux)
          ENABLE_SELINUX=1
          ;;
                    *)
          show_help
          echo "[ERROR] Invalid option!"
          exit 1
          ;;
  esac

  shift
done

main
exit 0
