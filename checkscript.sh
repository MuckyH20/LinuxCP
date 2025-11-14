#! /bin/bash

#CIS Hardening Scripts. Snapshot before running
#https://github.com/Nima-hasanzadeh/CIS-Ubuntu-22/blob/main/Pliers.bash
#https://github.com/search?q=CIS+Ubuntu+Hardening+Script&type=repositories&s=updated&o=desc
#https://github.com/konstruktoid/hardening
#https://github.com/algeriabot/cyberpatriot/tree/main
#https://github.com/ansible-lockdown/UBUNTU22-CIS-Audit/tree/devel

# 1.https://codeberg.org/easw/cyberpatriot/src/branch/main/cyberpatriots/checkscript.sh#

# Alright, I do not know how many times I've gone through this process
# I keep writing, and writing, and rewriting my scripts and checklists.
# Inevitably it gets messy, I'll discover something new that means it
# should be reorganized or I'll break something in my script. Its just
# a mess. So I'm restarting...again. But this time I have goals!
# So here are my goals for this new rewrite:
## Organize by order of when it should be done
## Make it a runnable script i.e. all descriptions be echo statements
## or comments
## Have description for whats happening
## But also to not spiral endlessly
## Make it modular, so you can turn on and off parts of the script
## Don't break the computer

function pause() {
    echo -n "Press Enter to continue: "
    read
    clear
}

function editfile() {
    echo "Use the above lines (if any) to edit the next file as needed"
    pause
    cp $1 $(pwd)/
    micro $1
}

function listusers() {
    cat /etc/passwd | cut -d: -f1
}

function editdir() {
    for file in $(ls $1)
    do
	editfile "$1/$file"
    done
}

function ask() {
    echo -n $1 " (y,N): "
    read answer
    if [ "${answer^^}" == "Y" ] || [ "${answer^^}" == "YE" ] || [ "${answer^^}" == "YES" ]
    then
	$2
    fi
}

function reinstall() {
    echo "Reinstalling package $1"
    apt purge $1 -y
    apt install $1 -y
}

function install() {
    for package in $@
    do
	echo "Searching for package $package"
	installed=$(dpkg -l | grep $package)
	if [ installed ]
	then
	    echo "Package $package already exists!"
	    ask "Would you like to reinstall the package $package" "reinstall $package"
	else
	    apt install $package -y
	fi
    done
}

function purgePackages() {
    for package in $1
    do
    	apt purge $package -y
    done

}


function backup() {

   if !(test -f nondefaultfiles); then
        echo "Making backups of essential files"
        cp /etc/passwd passwd
        cp /etc/shadow shadow
        cp /etc/group group
        cp /etc/gshadow gshadow
        cp /etc/sudoers sudoers
        pause

        dpkg-query -W -f='${Conffiles}\n' '*' | awk 'OFS="  "{print $2,$1}' | md5sum -c 2>/dev/null | awk -F': ' '$2 !~ /OK/{print $1}' > nondefaultfiles
        cat nondefaultfiles
        echo "This is a list all of the configuration files that have been changed by the cyberpatriot folks, these should be investigated, this list has been saved to $(pwd)/nondefaultfiles for your future reference"
        pause
    else
        echo "Script has already been run, skipping backups..."
        pause
    fi
}

function setup() {
    apt install micro
}


function forensicQuestions() {
    ## Read the README and do Forensics questions
    echo ""
    echo "Read the README then do all of the Forensics questions, then fix any insecurities in the forensics questions BEFORE CONTINUING"
    echo "Take notes on neccessary services, users, and any other important information."
    echo "Forensics questions can point you towards other vulnerabilities. Keep this in mind. (ex: a media file, find a hidden message, find a backdoor(could be pam edit or generally without port), etc)" 
    echo "https://gchq.github.io/CyberChef/"
    pause
}

function autoUpdates() {
    ## Automatically check for updates
    echo "Using the next window enable check for updates daily, download and install automatically security updates, and display immediatly other updates"
    software-properties-gtk
    pause
}

function fixSources() {
    ## Fix the sources
    echo "Fixing bad sources"
    echo "
    Using the next files check for suspicious entries for repositories
    "

    editfile /etc/apt/sources.list
    editdir /etc/apt/sources.list.d/
    editdir /etc/apt/apt.conf.d/

    ## GPG keys
    echo "Take a look at the apt sources keys"
    apt-key list
    pause
}

function updateSystem() {
    ## Update system
    echo "Updating the system"
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y
    snap refresh
    pause
}

function installAuthorizedPackages() {
    ## Install apt packages
    echo "Installing packages for configuring apt"
    apt install apt-listbugs -y
    apt install apt-listchanges -y
    pause
}


function purgeUnauthorizedPackages() {
    ## Deleting unauthorized packages(CHANGE PACKAGES IF CRITICAL SERVICE PERSISTS)
    echo "Deleting unauthorized default packages"
    # fakeroot? sane? sane-utils? ppp?
    badDefaults=(aisleriot cups "cups-*" "*-cups" ftp vsftp gnome-mahjongg gnome-mines gnome-sudoku remmina "remmina*" samba sambashare "samba-*" tcpdump telnet tcpd netcat nc netcat "netcat*" smbd snmpd "openssh-*" openssh-server ssh avahi "avahi-*" slapd ldap "ldap-*" nfs nfs-common nfs-kernel-server rsync talk irc nfs-server "nfs-*" rpcbind bind9 apache2 dovecot smbd squid snmpd inetutiles-inetd)
    for package in $badDefaults
    do
        apt purge $package
    done
    apt purge --autoremove
    apt list --installed | cut -d/ -f1 > installed
    diff defaults installed | grep ">"
    echo "Above is a list of nondefault packages"
    echo "Delete unauthorized packages be sure to get all tcps"
    pause
}

function unauthorizedFiles() {
    ## Unauthorized files
    echo "Removing unauthorized files"
    ls -alR /home/*/*
    echo "Above is a list of all files in the home directory"
    echo "Remove all unauthorized files and investigate files with strange ownership or permissions"
    pause
}

function securityPackages() {
    ## Install security packages
    echo "Installing PAM packages"
    apt upgrade libpam-runtime -y
    apt upgrade libpam-modules -y
    apt install libpam-tmpdin -y
    apt install libpam-usb -y
    apt install libpam-pwquality -y
    pause
}

function pamConfiguration() {
    ## PAM configuration
    echo "Configuring PAM"
    echo "
    # here are the per-package modules (the "Primary" block)

# Enforces password complexity and policies
password    required                        pam_pwquality.so reject_username 				enforce_for_root maxclassrepeat=5 maxsequence=5 maxrepeat=3 dcredit=-1 ocredit=-1 			lcredit=-1 ucredit=-1 minlen=10 difok=5 retry=3

# Enforces strong password hashing and prevents password reuse
password    required                        pam_unix.so obscure sha512 remember=12 			use_authtok

# Enforces password history to prevent recent reuse of passwords
password    required                        pam_pwhistory.so remember=12 				enforce_for_root use_authtok

password    sufficient                      pam_sss.so use_authtok

# here's the fallback if no module succeeds
password    requisite                       pam_deny.so

# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
password    required                        pam_permit.so

# and here are more per-package modules (the "Additional" block)
password    optional                        pam_gnome_keyring.so

# end of pam-auth-update config

# Log the last login and failed attempts for each user session
session     required                        pam_lastlog.so showfailed

(in nevermore minlen didnt work until appended but worked in aperture)

    "
    editfile /etc/pam.d/common-password
}

function passwordExpiration() {
    ## Password expiration
    echo "Configuring password expiration"
    useradd --defaults --inactive 30 --expiredate 90 --shell /bin/bash
    echo "
    PASS_MAX_DAYS 90
    PASS_MIN_DAYS 30
    PASS_WARN_AGE 7
    umask 027
    "
    editfile /etc/login.defs
}

function enforcePasswordPolicies() {
    ## Enforce password policy on current users
    echo "Enforcing password policy on current users"
    for user in $(listusers)
    do
        if [ $user != $mainUser ]
	then
            echo "Enforcing for user $user"
            chage --inactive 30 --mindays 30 --maxdays 90 --warndays 7 $user
	fi
    done
    pause

    ## Disabling password for current users
    echo "Disabling current users passwords and login"
    for user in $(listusers)
    do
        if [ $user != $mainUser ]
        then
            echo "Disabling password for $user"
            chage -d 0 $user
            usermod -L $user
            if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]
            then
                usermod -s /usr/sbin/nologin $user
            fi
            ask "Setting new password for $user" "passwd $user"
        fi
    done
    pause
}

function auditPolicy() {
    ## Audit policy
    echo "installing audit packages"
    apt install auditd -y
    systemctl enable auditd
    echo "Enable Audit at startup"
    echo "
    add => GRUB_CMDLINE_LINUX=\"audit=1\"
    "
    editfile /etc/default/grub
    update-grub
    echo "Setting Auditing settings"
    echo "
    max_log_file = 6
    space_left_action = email
    action_mail_acct = root
    admin_space_left_action = halt
    max_log_file_action = keep_logs
    local_events=yes
    "
    editfile /etc/audit/auditd.conf

    if [ $systembit -eq 32 ]
    then
        echo "
    -a always,exit -F arch=b32-S adjtimex -S settimeofday -S stime -k time-change
    -a always,exit -F arch=b32 -S clock_settime -k time-change
    -w /etc/localtime -p wa -k time-change

    -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
    -w /etc/issue -p wa -k system-locale
    -w /etc/issue.net -p wa -k system-locale
    -w /etc/hosts -p wa -k system-locale
    -w /etc/sysconfig/network -p wa -k system-locale

    -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S setxattr-S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

    -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
    -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

    -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

    -w /sbin/insmod -p x -k modules
    -w /sbin/rmmod -p x -k modules
    -w /sbin/modprobe -p x -k modules
    -a always,exit -F arch=b32 -S init_module -S delete_module -k modules
    "
    else
        echo "
    -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
    -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
    -a always,exit -F arch=b64 -S clock_settime -k time-change
    -a always,exit -F arch=b32 -S clock_settime -k time-change
    -w /etc/localtime -p wa -k time-change

    -a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
    -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
    -w /etc/issue -p wa -k system-locale
    -w /etc/issue.net -p wa -k system-locale
    -w /etc/hosts -p wa -k system-locale
    -w /etc/sysconfig/network -p wa -k system-locale

    -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
    -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

    -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
    -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
    -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
    -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

    -a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

    -a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
    -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

    -w /sbin/insmod -p x -k modules
    -w /sbin/rmmod -p x -k modules
    -w /sbin/modprobe -p x -k modules
    -a always,exit -F arch=b64 -S init_module -S delete_module -k modules
    "
    fi
    echo "-w /sbin/insmod -p x -k modules
    -w /sbin/rmmod -p x -k modules
    -w /sbin/modprobe -p x -k modules
    -a always,exit -F arch=b64 -S init_module -S delete_module -k modules

    -w /etc/apparmor/ -pwa -k MAC-policy
    -w /etc/apparmor.d/ -p wa -k MAC-policy

    -w /var/log/faillog -p wa -k logins
    -w /var/log/lastlog -p wa -k logins
    -w /var/log/tallylog -p wa -k logins

    -w /var/run/utmp -p wa -k session
    -w /var/log/wtmp -p wa -k logins
    -w /var/log/btmp -p wa -k logins

    -w /etc/sudoers -p wa -k scope
    -w /etc/sudoers.d/ -p wa -k scope

    -w /var/log/sudo.log -p wa -k actions

    -e 2
    "
    editfile /etc/audit/audit.rules
    service auditd restart
    pause
}

function accountLockoutPolicy() {
    ## Account lockout policy
    echo "Set account lockout policy(use faillock)"
    echo "
    auth	required	pam_tally2.so deny=5 onerr=fail audit even_deny_root lock_time=1200 unlock_time=1800
    above is outdated use

    Enforce account lockout policy in /etc/pam.d/common-auth

		MUST COME FIRST

	   	
     		sudo touch /usr/share/pam-configs/faillock
     		sudo micro /usr/share/pam-configs/faillock

     		In /usr/share/pam-configs/faillock type the following text:
		Name: Enforce failed login attempt counter
		Default: no
		Priority: 0
		Auth-Type: Primary
		Auth:
		    [default=die] pam_faillock.so authfail
		    sufficient pam_faillock.so authsucc

     		sudo touch /usr/share/pam-configs/faillock_notify
     		sudo micro /usr/share/pam-configs/faillock_notify

     		In /usr/share/pam-configs/faillock_notify type the following text:
		Name: Notify on failed login attempts
		Default: no
		Priority: 1024
		Auth-Type: Primary
		Auth:
		    requisite pam_faillock.so preauth

     		sudo pam-auth-update

     		Select,with the spacebar, Notify on failed login attempts, and Enforce failed login attempt counter, and then select <Ok>
     		![image](https://github.com/user-attachments/assets/f00b9bff-6cef-4dd5-9438-deef48485777)

    "
    editfile /etc/pam.d/common-auth
    echo "
    TMOUT=600
    umask 027
    " >> /etc/bash.bashrc
    echo "
    TMOUT=600
    umask 027
    " >> /etc/profile
#    pause
}

function bannerConfig() {
    ## Set banners
    echo "Setting banners"
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
    pause
}

function usbSecurity() {
    ## Configure USB security
    echo "Configuring USB security"
    service autofs stop
    systemctl disable autofs
    apt install usb-storage -y
    apt install USBGaurdd -y
    systemctl enable USBGaurdd
    pause
}

function filePermissions() {
    ## Setting file permissions and ownership
    echo "Setting correct file permissions and ownership"
    chown root:root /etc/passwd
    chmod 644 /etc/passwd
    chown root:root /etc/shadow
    chmod o-rwx,g-wx /etc/shadow
    chown root:root /etc/group
    chmod 644 /etc/group
    chown root:shadow /etc/gshadow
    chmod o-rwx,g-rw /etc/gshadow
    chown root:root /etc/passwd-
    chmod u-x,go-wx /etc/passwd-
    chown root:root /etc/shadow-
    chown root:shadow /etc/shadow-
    chmod o-rwx,g-rw /etc/shadow-
    chown root:root /etc/group-
    chmod u-x,go-wx /etc/group-
    chown root:root /etc/gshadow-
    chown root:shadow /etc/gshadow-
    chmod o-rwx,g-rw /etc/gshadow-
    pause
}

function lockUserAccounts() {
    ## Locking user accounts
    echo "Locking user accounts"
    echo "Configuring root"
    usermod -s /bin/false root
    usermod -L root
    usermod -g 0 root
    echo "
    Lock root to physical consoles
    "
    editfile /etc/securetty
    echo "Lock Guest account"
    echo "
    allow-guest=false
    "
    if [ -d /etc/lightdm/ ]
    then
        editfile /etc/lightdm/lightdm.conf
    else
    	echo "
    allowroot=false
    "
        editfile /etc/gdm3/custom.conf
        echo "
    DELETE LINE => auth sufficient pam_succeed_if.so user ingroup nopasswdlogin
    "
        editfile /etc/pam.d/gdm-password
    fi
}

function groupUserConfig() {
    ## Group and User config
    echo "
    At this time:
    add authorized users			adduser [username]
    delete unauthorized users			deluser [username]
    add authorized groups			groupadd [group]
    delete unauthorized groups			groupdel [group]
    add authorized users to groups		usermod -aG [group] [user]
    remove unauthorized users from groups	gpasswd -d [user] [group]
    also check shadow for password logins on sys users
    "

    echo "
    Compare /etc/passwd and /etc/group to the readme, or use a GUI if easier.

    Look out for UID 0 and hidden users! If you find a user with UID 0, edit the /etc/passwd file. 
    Any user with UID 0 has root privileges, which is a security risk!

    Commands to find unauthorized users/admins/groups:
    - Find unauthorized admins: getent group | grep sudo
    - Not comprehensive, but check group privileges: getent group | grep :0
    - Find unauthorized root users: getent passwd | grep :0
    - List all users: getent passwd | grep /home
    "
    pause
}

function sudoConfig() {
    ## Configuring Sudo
    echo "Configure sudo"
    echo "
    Defaults    requiretty
    Defaults    use_pty
    Defaults	lecture=\"always\"
    Defaults	log_input,log_output
    Defaults	passwd_tries=3
    Defaults    passwd_timeout=1
    root ALL=(ALL) ALL
    %wheel ALL=(ALL) ALL
    %sudo ALL=(ALL) ALL
    "
    pause
    visudo
    clear
    echo "
    Check the files in the /etc/sudoers.d/ directory the script will automatically take you through these files:
    "
    echo "	1. Check /etc/sudoers and /etc/sudoers.d for unauthorized users and groups.

		1. Remove any instances of nopasswd and !authenticate, these allow sudo use without authentication

		1. Any commands listed can be run without a password (ex: /bin/chmod)

		1. Group lines are preceded by %

     		1. General file check if unauth user has sudo access like user1 ALL=(ALL) ALL "
    
    ls /etc/sudoers.d/
    pause
    editdir /etc/sudoers.d/
}

function firewallConfig() {
    ## Firewall configuration
    echo "Configure the firewall"
    apt install ufw -y
    apt install iptables -y

    iptables -F
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A INPUT -s 127.0.0.0/8 -j DROP
    iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
    iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
    iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
    iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
    ####iptables -A INPUT -p <protocol> --dport <port> -m state --state NEW -j ACCEPT
    ####ip link set <interface> down

    ufw enable
    ufw default deny incoming
    ufw logging full
    echo "
    IPV6=yes
    "
    editfile /etc/default/ufw
    echo "This script should allow the critical services you agree to configure through the firewall, however to be sure use ufw [allow/deny] [program/port/ip address] as needed for this situation i.e. allow critical services"
    pause
}

function findingBackdoors() {
    ## Backdoors
    echo "Finding backdoors"
    apt install nmap -y
    nmap -sV -f -p- 127.0.0.1
    netstat -tulpn
    echo "At this time research suspicious port numbers, some userful commands are:
    ps -aux | grep [process id] ::::::::: finds which file started a process
    "
    pause
    apt purge nmap -y
    clear
}

function hostFileConfig() {
    ## Configure host files
    echo "Configure host files"
    echo "
    Remove non default entries in /etc/host
    "
    editfile /etc/hosts
    echo "
    Remove non default entries in /etc/hosts.allow
    "
    editfile /etc/hosts.allow
    echo "
    ALL: ALL
    "
    editfile /etc/hosts.deny
}

function serviceConfig() {
    ## Services
    echo "Configuring services"
    service --status-all
    echo "Remove unwanted services with 'systemctl disable [service] && systemctl stop [service] then uninstall their packages wiht apt purge [service's package]"
    pause
    echo "
    remove anything starting with chargen | daytime | discard | echo | time | shell, login, exec | talk, ntalk | telnet | tftp
    "
    editfile /etc/inetd.conf
    editdir /etc/inetd.d/
    echo "
    write disable = yes for all chargen | daytime | discard | echo | time | rsh, rloging, rexec | talk | telnet | tftp services
    "
    editfile /etc/xinetd.conf
    editdir /etc/xinetd.d/
    systemctl disable xinetd
    apt remove openbsd-inetd
    echo "Setting up good services"
    apt install ntp -y
    apt install chrony -y
    systemctl enable ntp
    systemctl enable chrony
    echo "
    restrict -4 default kod nomodify notrap nopeer noquery
    restrict -6 default kod nomodify notrap nopeer noquery
    server <remove-server>
    "
    editfile /etc/ntp.conf
    echo "
    RUNASUSER=ntp
    "
    editfile /etc/init.d/ntp
    echo "
    server <remote-server>
    "
    editfile /etc/chrony/chrony.conf
    echo "Disabling known bad services"
    systemctl disable avahi-daemon #remove?????
    systemctl disable cups # remove cups? configuring printing?
    systemctl disable isc-dhcp-server
    systemctl disable isc-dhcp-server6
    systemctl disable slapd
    systemctl disable nfs-server
    systemctl disable rpcbind
    systemctl disable bind9
    systemctl disable vsftpd
    systemctl disable apache2
    systemctl disable dovecot
    systemctl disable smbd
    systemctl disable squid
    systemctl disable snmpd
    echo "
    RECIVING MAIL section => inet_interfaces = loopback-only
    "
    editfile /etc/postfix/main.cf
    systemctl restart postfix
    systemctl disable rsync
    systemctl disable nis
    apt purge nis rsh-client rsh-redone-client talk telnet ldap-utils -y
    pause
}

## Configure OPENSSH-SERVER
function openssh-server() {
    echo "Configuring openssh-server"
    echo "This script may reinstall openssh-server, reinstalling will delete the configuration files of the current set up, these files have been saved to your current directory"
    cp -r /etc/ssh/ ssh/
    install openssh-server
    service sshd enable
    service sshd start
    chown root:root /etc/ssh/sshd_config
    chmod og-rwx /etc/ssh/sshd_config
    echo "
# out AcceptEnv
#KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
#Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
UsePrivilegeSeparation sandbox
Subsystem sftp  internal-sftp -f AUTHPRIV -l INFO
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
UseDNS no
Compression no
TCPKeepAlive no
AllowAgentForwarding no
PermitRootLogin no
Port 8808
ForwardX11 no
Protocol 2
LogLevel INFO # Verbose
X11Forwarding no
MaxAuthTries 2
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 60
Banner /etc/issue.net
ListenAddress 0.0.0.0
MaxSessions 2
MaxStartups 2
PasswordAuthentication yes/no ???????
PubkeyAuthentication yes/no same as above but no if nothing is said
AllowUsers <userlist>
AllowGroups <grouplist>
DenyUsers <userlist>
DenyGroups <grouplist>
"
    editfile /etc/ssh/sshd_config
    service sshd restart
    sshd -T
    ufw allow 8808
    systemctl reload sshd
    pause
}

## Configure mysql database serverd
function mysql-server () {
    echo "Configuring mysql-server"
    echo "This will script may reinstall mysql, reinstalling will delete the configuration files of the current set up, these files have been saved to your current directory"
    cp -r /etc/mysql/ mysql/
    install mysql-server
    service mysql enable
    service mysql start
    echo "
/etc/mysql/mysql.conf.d/mysqld.cnf
bind-address = 127.0.0.1
user = mysql
port = 1542
local_infile = 0
symbolic-links = 0
default_password_lifetime = 90
"
    editfile /etc/mysql/mysql.conf.d/mysqld.cnf
    ufw allow 1542
    service mysql restart
    pause
    #should we block foriegn computers from accessing mysql?
}

## Configuring Apache Web Server
function apache2 () {
    echo "Configuring apache2 web server"
    ask "Would you like to uninstall v1 of apache server, if your current set up is on this, it will be removed and lost, so back it up" "apt purge apache -y"
    echo "This script may reinstall apache2, reinstalling will delete the configuration files of the current set up, these files have been saved to your current directory"
    cp -4 /etc/apache2 apache2/
    install apache2
    service apache2 start
    service apache2 enable
    ufw allow "Apache Full"
    apt install libapache2-mod-security2
    mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
    useradd -r -s /bin/false apache
    groupadd apache
    useradd -G apache apache
    chown -R apache:apache /opt/apache
    chmod -R 750 /etc/apache2/*
    chown -R root /etc/apache2
    echo "
ServerTokens Prod
ServerSignature Off
FileETag None
User apache
Group apache
TraceEnable off
Timeout 60
Header always append X-Frame-Options SAMEORIGIN
Header set X-XSS-Protection "1; mode=block"
<Directory />
Options –Indexes -Includes
AllowOverride None
</Directory>
<LimitExcept GET POST HEAD>
deny from all
</LimitExcept>
"
    editfile /etc/apache2/apache2conf
    echo "You will have to configure https by yourself the following configuration...I have no idea how or if it works"
    echo "
<Directory /opt/apache/htdocs>
Options None
</Directory>
<Directory />
Options -Indexes
AllowOverride None
</Directory>
"
    # I need to get the correct location for this file
    editfile /etc/apache2/httpsd.conf
    service apache2 restart
    pause
}

## Configuring postfix
function postfix () {
    echo "Configuring postfix"
    echo "This will script may reinstall postfix, reinstalling will delete the configuration files of the current set up, these files have been saved to your current directory"
    cp -r /etc/postfix/ postfix/
    install postfix
    echo "
inet_interfaces = loopback-only
"
    editfile /etc/postfix/main.cf
    service postfix restart
}

## Configuring nginx
function nginx () {
    echo "Configuring nginx web server"
    echo "This will script may reinstall postfix, reinstalling will delete the configuration files of the current set up, these files have been saved to your current directory"
    cp -r /etc/nginx nginx/
    install nginx
    echo "
server_tokens off;
"
    editfile /etc/nginx/nginx.conf
    service nginx restart
    pause
}

function cronConfig() {
    ## Configuring cron
    echo "Configuring cron"
    systemctl enable cron
    rm /etc/cron.deny
    rm /etc/at.deny
    touch /etc/cron.allow
    touch /etc/at.allow
    chmod og-rwx /etc/cron.allow
    chmod og-rwx /etc/at.allow
    chown root:root /etc/cron.allow
    chown root:root /etc/at.allow
    chown root:root /etc/crontab
    chmod og-rwx /etc/crontab
    chown root:root /etc/cron.hourly
    chmod og-rwx /etc/cron.hourly
    chown root:root /etc/cron.daily
    chmod og-rwx /etc/cron.daily
    chown root:root /etc/cron.weekly
    chmod og-rwx /etc/cron.weekly
    chown root:root /etc/cron.monthly
    chmod og-rwx /etc/cron.monthly
    chown root:root /etc/cron.d
    chmod og-rwx /etc/cron.d
    pause
}

function mountConfig() {
    ## Mount systems securely
    echo "Mounting systems securely"
    mount -o remount,noexec /dev/shm
    mount -o remount,nosuid /dev/shm
    mount -o remount,nodev /dev/shm
    mount -o remount,nodev /tmp
    mount -o remount,nosuid /tmp
    mount -o remount,nodev /var/tmp
    mount -o remount,nosuid /var/tmp
    mount -o remount,noexec /var/tmp
    mount -o remount,nodev /home
    none /run/shm tmpfs defaults,ro 0 0
    pause
}

function kernelConfig() {
    ## Configuring Kernel settings
    echo "Configuring kernel settings"
    echo "
    fs.protected_hardlinks=1
    fs.protected_symlinks=1
    fs.suid_dumpable=0
    kernel.exec-shield=1
    kernel.randomize_va_space=2
    net.ipv4.ip_forward=0
    net.ipv4.conf.all.rp_filter=1
    net.ipv4.conf.all.accept_source_route=0
    net.ipv4.conf.all.send_redirects=0
    net.ipv4.conf.all.log_martians=1
    net.ipv4.conf.all.secure_redirects=0
    net.ipv6.conf.all.accept_ra=0
    net.ipv4.conf.default.secure_redirects=0
    net.ipv4.conf.default.send_redirects=0
    net.ipv4.conf.default.log_martians=1
    net.ipv4.conf.default.rp_filter=1
    net.ipv4.icmp_echo_ignore_broadcasts=1
    net.ipv4.icmp_ignore_bogus_error_messages=1
    net.ipv4.icmp_ignore_bogus_error_responses=1
    net.ipv4.tcp_syncookies=1
    net.ipv6.conf.all.accept_redirects=0
    net.ipv6.conf.all.disable_ipv6 = 1 # Careful! This disables IPv6
    net.ipv6.conf.default.accept_ra=0
    net.ipv6.conf.default.accept_redirects=0
    "
    editfile /etc/sysctl.conf
    echo "* hard core 0"
    editfile /etc/security/limits.conf
    echo "
    install dccp /bin/true
    install sctp /bin/true
    install rds /bin/true
    install tipc /bin/true
    install cramfs /bin/true
    install freevxfs /bin/true
    install jffs2 /bin/true
    install hfs /bin/true
    install hfsplus /bin/true
    install udf /bin/true
    "
    editfile /etd/modprobe.d/CIS.conf
    rmmod udf
    rmmod hfsplus
    rmmod hfs
    rmmod jffs2
    rmmod freevxfs
    rmmod cramfs
    echo "
    order bind,hosts
    multi on
    nospoof on
    "
    editfile /etc/host.conf
    echo "
    make server 8.8.8.8
    "
    editfile /etc/resolv.conf
    echo "
    exit 0
    "
    editfile /etc/rc.local
}
##

function fileAuditing() {
    ## Audit Verious files
    echo "Auditing Verious files you should look into these files they are saved to your running
    directory"
    echo "List of world writable files"
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 > worldwritable
    cat worldwritable
    echo "
    List of unowned files"
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser > unowned
    cat unowned
    echo "
    List of ungrouped files"
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup > ungrouped
    cat ungrouped
    echo "
    List of SUID executables"
    df --local -P | awk {'if (NR!=1)print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 > SUID
    cat SUID
    echo "
    Lit of SGID executables"
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 > SGID
    cat SGID
    pause
}

function securityAuditing() {
    ## Security auditing
    echo "Installing and running security auditing software"
    apt install rkhunter -y
    apt install lynis -y
    apt install clamav -y
    function security-auditing () {
        rkhunter --update --propupd
        rkunter --check
        lynis -c
        freshclam
        clamscan -r --remove
    }
    ask "Would you like to run the security auditing softwares, this will take a long time" security-auditing
    pause

    echo "
    You have reached the end of this script! Now for some final suggestions:
    restart the system so your kernel modifications can take effect
    "z
}

function media() {
    echo "Searching for and removing media files interactively..."
    # Directories to exclude
    excluded_dirs="/opt /usr /var"
    # Log file for removed files
    log_file="/var/log/media_removal.log"

    for ext in mp3 mov mp4 avi mpg mpeg flac m4a flv ogg gif png jpg jpeg; do
        echo "Searching for *.$ext files..."
        find / -name "*.$ext" -type f \
            $(printf "! -path %s " $excluded_dirs) \
            -exec rm -i {} \; | tee -a $log_file
    done
    echo "Media removal process completed. See $log_file for details. Also look for other types of files in your home dir use ui"
}



function main() {

echo "Welcome to this script! Here are just a few notes:

Every file you edit has a copy made in the directory you ran this script from

"
pause

## Veriables
echo "Downloading dependencies"
apt install curl -y

## Find out if system is 32 bit or 64 bit
case $(uname -m) in
    "i686") systembit=32;;
    "i386") systembit=32;;
    "x86_64") systembit=64;;
esac

#read -p "What version of ubuntu are you using (14/16/18/22): " distro
#if [ $distro == "12" ]
#then
 #  curl http://releases.ubuntu.com/precise/ubuntu-12.04.5-desktop-amd64.manifest | cut -f1 > defaults
#elif [ $distro == "14" ]
#then
#    curl http://releases.ubuntu.com/trusty/ubuntu-14.04.6-desktop-amd64.manifest | cut -f1 > defaults
#elif [ $distro == "16" ]
#then
#    curl http://releases.ubuntu.com/xenial/ubuntu-16.04.7-desktop-amd64.manifest | cut -f1 > defaults
#elif [ $distro == "18" ]
#then
#     curl http://releases.ubuntu.com/bionic/ubuntu-18.04.5-desktop-amd64.manifest | cut -f1 > defaults
#else
#    curl https://releases.ubuntu.com/jammy/ubuntu-22.04.5-desktop-amd64.manifest | cut -f1 > defaults
#fi

read -p "What is the name of your main user account: " mainUser

### run
#backup
#setup
#forensicQuestions
#autoUpdates
#fixSources
updateSystem
installAuthorizedPackages
purgeUnauthorizedPackages
unauthorizedFiles
#media
securityPackages
pamConfiguration
passwordExpiration
enforcePasswordPolicies
auditPolicy
accountLockoutPolicy
bannerConfig
usbSecurity
filePermissions
lockUserAccounts
groupUserConfig
sudoConfig
firewallConfig
findingBackdoors
hostFileConfig
serviceConfig
ask "Is openssh-server a critical service" openssh-server
ask "Is mysql-server a critical service" mysql-server
ask "Is apache2 a critical service" apache2
ask "Is postfix a critcal service" postfix
ask "Is nginx a critical service" nginx
cronConfig
mountConfig
kernelConfig
fileAuditing
securityAuditing
}

if [[ $(whoami) != "root" ]]
then
	echo "This script was no run as root...running as root"
	sudo $0
else
	echo "Root check passed, running..."
	main
fi

### Todo
# only change passwords for users with id over 1000
