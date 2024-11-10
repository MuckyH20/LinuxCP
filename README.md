# LinuxCP
# SixSwords Linux Checklist

## Notes

Preferred text editor: sudo apt install micro
^e set colorscheme material-tc

Assume root permissions are needed for most commands. You can use `sudo` or become root with `su`.

I would no longer recommend running `apt-get dist-upgrade` in competition. They may call it intelligent, but it has a bad track record of breaking critical services.

This script heavily borrows from [Forty-Bot Linux Checklist](https://github.com/Forty-Bot/linux-checklist)

Enable pasting if not already enabled `sudo apt install open-vm-tools open-vm-tools-desktop -y`

So far in this checklist you are mostly adding to text files, but remember there may be things to be removed within. For example, in pam/common-auth in 'auth [success=2 default=ignore] pam_unix.so nullok' nullok allows empty passwords to log in so it must be removed. You have to actually understand these services. STIGS and CIS have baselines. Gotta find which modules are and where they should be.

## Checklist

1. Read the readme

	Take notes on neccessary services, users, and any other important information.



1. Do the Forensics Questions

	Forensics questions can point you towards other vulnerabilities. Keep this in mind. (ex: a media file, find a hidden message, find a backdoor, etc)



1. Account Configuration

	1. Lock the root account from direct log in. Possibly just change shell to nologin, comp reqs.

		`$ passwd -l root`

	1. If lightdm exists, disable the guest account in `/etc/lightdm/lightdm.conf` and then restart your session with sudo restart lightdm. Check for other display managers, as then you will have to harden those.

		```
		allow-guest=false
		greeter-hide-users=true
		greeter-show-manual-login=true
		autologin-user=none
		```

	1. Compare `/etc/passwd` and `/etc/group` to the readme. Or use gui, prob easier. 

		Look out for uid 0 and hidden users! if you find user with uid 0, edit the /etc/passwd file. If anyone had uid 0, means they are root that is not good!! You will need to edit /etc/passwd file.

        1. Find unauth users/admins/groups
                look for unauth admin: `getent group | grep sudo`
           	not comprehensive, group privs given in sudoers`getent group | grep :0`
           	get unauth root: `getent passwd | grep :0`
                get all users: `getent passwd | grep /home`

	1. Delete unauthorized users

		```
		$ userdel -r $user
		$ groupdel $user
		```

	1. Add users

		```
		$ useradd -G $group1,$group2 $user
		$ passwd $user
		```
  	

	1. Remove unauthorized users from adm and groups

		`$ gpasswd -d $user $group`

	1. Add authorized users to groups

		`$ gpasswd -a $user $group`

	1. Check `/etc/sudoers` and `/etc/sudoers.d` for unauthorized users and groups.

		1. Remove any instances of `nopasswd` and `!authenticate`, these allow sudo use without authentication

		1. Any commands listed can be run without a password (ex: /bin/chmod)

		1. Group lines are preceded by `%`

     		1. General file check if unauth user has sudo access like user1 ALL=(ALL) ALL

	1. Wait to change user passwords until after password policy!

        1. In /etc/passwd for root, change /bin/bash to /sbin/nologin(double check competition reqs)

   
           

1. Password Policy

	1. Change password expiration requirements in `/etc/login.defs`

		```
		PASS_MAX_DAYS 90
		PASS_MIN_DAYS 10
		PASS_WARN_AGE 7
		```

	1. Add password history, minimum password length, and password complexity requirements in `/etc/pam.d/common-password`

		**INSTALL PWQUALITY PRIOR TO CHANGING COMMON-PASSWORD**: 

		`$ apt install libpam-pwquality`

		```
		# Enforces strong password hashing and prevents password reuse
		password    required    pam_unix.so obscure sha512 remember=12 use_authtok

		# Enforces password complexity and policies
		password    required    pam_pwquality.so reject_username enforce_for_root maxclassrepeat=3 maxsequence=3 maxrepeat=3 dcredit=-1 ocredit=-1 lcredit=-1 ucredit=-1 minlen=16 difok=5 retry=3 use_authtok

		# Enforces password history to prevent recent reuse of passwords
		password    required    pam_pwhistory.so remember=12 enforce_for_root use_authtok

		# Log the last login and failed attempts for each user session
		session     required    pam_lastlog.so showfailed




		```

	1. Enforce account lockout policy in `/etc/pam.d/common-auth`

		**MUST COME FIRST**

	   	```
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


	1. Check minimum and maximum password ages in `/etc/shadow`

		Use `chage` to change password expiration.

		`$ chage -m $MIN -M $MAX $user`

	1. Script
	```
    	#!/bin/bash

	# Set default inactivity period to 30 days for new users
	useradd -D -f 30

	# Enforce 30-day inactivity for all existing users
	for user in $(awk -F: '{ if ($3 >= 1000) print $1 }' /etc/passwd); do
	    chage --inactive 30 "$user"
	done

	# Set non-login shell for system users (UID < 1000)
	for user in $(awk -F: '{ if ($3 < 1000) print $1 }' /etc/passwd); do
	    usermod -s /usr/sbin/nologin "$user"
	done

	# Ensure no user has a password change date in the future
	for user in $(awk -F: '{ if ($3 >= 1000) print $1 }' /etc/passwd); do
	    # Check the last password change date
	    last_change=$(chage -l "$user" | grep "Last password change" | cut -d: -f2)
	    # Convert to a comparable date format
	    if [[ $(date -d "$last_change" +%s) -gt $(date +%s) ]]; then
 	       # If in the future, reset to today
    	    chage -d 0 "$user"
 	   fi
	done




1. Check for unauthorized media

	1. Find media files

		`$ find / -iname "*.$extension" or locate *$extension`

	1. Remove media files, backdoors, PII files, etc

		`$ ls -alR /home/*/*` 

		**There also may be unauthorized network shares not under the /home directory**
	1. Files/directories
		```
		sudo rm -f [file]
		sudo rm -rf [directory]
		Apt-mark to see if manually installed or held
		Turn on automatic backup
		```
  	1. Check Important Files Perms(Ex: /etc/shadow) and change them to security standard with chmod(CIS Benchmarks)
  




1. Network Security

	1. Enable and configure UFW

		```
		$ ufw default deny incoming
		$ ufw default allow outgoing
		$ ufw allow $port/service
		$ ufw delete $rule
		$ ufw logging on
		$ ufw logging high
		$ ufw enable
		```

	1. Check `/etc/hosts` file for suspicious entries

	1. Prevent IP Spoofing

		`$ echo "nospoof on" >> /etc/host.conf`







1. Package Management

	1. Verify the repositories listed in `/etc/apt/sources.list & /etc/apt/sources.list.d/`

	1. Verify Repositories

		1. Check apt repository policy

			`$ apt-cache policy`

		1. Check apt trusted keys

			`$ apt-key list`

	1. Updates

		```
		$ apt-get update
		$ apt-get -y upgrade
		$ apt-get -y dist-upgrade
		```
  	1. Configure updates with software-properties-gtk
  		Check for updates daily
		Download and install automatically for security updates
		Display immediatly for other updates
	
        1. sudo apt update & sudo apt upgrade or gui to update apps(firefox, mail, etc)
           
		**Look for points for packages mentioned in the README, along with bash (if vulnerable to Shellshock), the kernel, sudo, and sshd**

	1. Verify binaries match with `debsums`

		1. Install `debsums`

			`$ apt-get install debsums`

		1. Generate checksums for packages that don't come with them

			`$ debsums -g`

		1. Verify checksums for all binaries

			`$ debsums -c`

		1. Verify checksums for binaries and config files *(false positives for legitimate changes by us)*

			`$ debsums -a`

	1. Remove unauthorized and unused packages

		1. Use deborphan to detect unneccessary packages(didnt work find better)

			1. Install deborphan

				`$ apt-get install deborphan`

			1. Search for unneccessary packages

				`$ deborphan --guess-all`

			1. Delete unneccessary data packages

				`$ deborphan --guess-data | xargs sudo apt-get -y remove --purge`

			1. Delete unneccessary libraries

				`$ deborphan | xargs sudo apt-get -y remove --purge`

		1. Look for hacking tools, games, and other unwanted/unneccessary packages

			```
   			$ apt list --installed | cut -d/ -f1
			$ apt-cache policy $package
			$ which $package
			$ dpkg-query -l | grep -E '^ii' | less
   			$ dpkg -l | grep hack
   			$ sudo apt-get remove/purge/autoremove [program name]
			```

		1. Ensure all services are required

			`service --status-all or systemctl list-units --type=service --state=active`
			`sudo systemctl disable --now $service`

		BAD STUFF

		`john, nmap, vuze, frostwire, kismet, freeciv, minetest, minetest-server, medusa, hydra, truecrack, ophcrack, nikto, cryptcat, nc, netcat, tightvncserver, x11vnc, nfs, xinetd`

		POSSIBLY BAD STUFF

		`samba, postgresql, sftpd, vsftpd, apache, apache2, ftp, mysql, php, snmp, pop3, icmp, sendmail, dovecot, bind9, nginx`

		MEGA BAD STUFF

		`telnet, rlogind, rshd, rcmd, rexecd, rbootd, rquotad, rstatd, rusersd, rwalld, rexd, fingerd, tftpd, telnet, snmp, netcat, nc`







1. Service & Application Hardening

	1. Configure OpenSSH Server in `/etc/ssh/sshd_config`

		```
		Protocol 2
		LogLevel VERBOSE
		X11Forwarding no
		MaxAuthTries 4
		IgnoreRhosts yes
		HostbasedAuthentication no
		PermitRootLogin no
		PermitEmptyPasswords no
		```

	1. Harden Firefox

  		1. block popups, look for concerning things
		1. 1) Open Firefox's settings
		1. 2) Go to "Privacy & Security"
		1. 3) At the bottom, check "Block dangerous and deceptive content" and all sub-checks
		

	1. Configure apache2 in `/etc/apache2/apache2.conf`

		```
		ServerSignature Off
		ServerTokens Prod
		```






  

1. Backdoor Detection and Removal

	1. `ss -tlnp`(dont forget sudo). Running as sudo gives process so you can directly find location with which or whereis and kill process and then delete file. Also must check for crontab. Check for crontab first. sudo pkill -f $process name and sudo rm /dir. ![image](https://github.com/user-attachments/assets/d541be11-b607-406b-9dc8-0d865103d414)


	1. If a port has `127.0.0.1:$port` in its line, that means it's connected to loopback and isn't exposed. Otherwise, there should only be ports which are specified in the readme open (but there probably will be tons more).

	1. For each open port which should be closed

		1. Find the program using the port

			`$ lsof -i $port`

		1. Locate where the program is running from

			`$ whereis $program`(if not showing could be cron)

		1. Find what package owns the file

			`$ dpkg -S $location`

		1. Remove the responsible package

			`$ apt-get purge $package`

		1. If there is no package, delete the file and kill the processes

			`$ rm $location; killall -9 $program`

		1. Verify the port is closed

			`$ ss -l`








1. Cron

	1. Check your user's crontabs

		`$ crontab -e`

	1. Check `/etc/cron.*/`, `/etc/crontab`, and `/var/spool/cron/crontabs/`

	1. Check init files in `/etc/init/` and `/etc/init.d/`

	1. Remove contents of `/etc/rc.local`

		`$ echo "exit 0" > /etc/rc.local`

	1. Check user crontabs

		`$ crontab -u $user -l`

	1. Deny users use of cron jobs

		`$ echo "ALL" >> /etc/cron.deny`

	1. install bum to check start up services










1. Kernel Hardening

	1. Edit the `/etc/sysctl.conf` file

		```
		fs.file-max = 65535
		fs.protected_fifos = 2
		fs.protected_regular = 2
		fs.suid_dumpable = 0
		kernel.core_uses_pid = 1
		kernel.dmesg_restrict = 1
		kernel.exec-shield = 1
		kernel.sysrq = 0
		kernel.randomize_va_space = 2
		kernel.pid_max = 65536
		net.core.rmem_max = 8388608
		net.core.wmem_max = 8388608
		net.core.netdev_max_backlog = 5000
		net.ipv4.tcp_rmem = 10240 87380 12582912
		net.ipv4.tcp_window_scaling = 1
		net.ipv4.tcp_wmem = 10240 87380 12582912
		net.ipv4.conf.all.accept_redirects = 0
		net.ipv4.conf.all.accept_source_route = 0
		net.ipv4.conf.all.log_martians = 1
		net.ipv4.conf.all.redirects = 0
		net.ipv4.conf.all.rp_filter = 1
		net.ipv4.conf.all.secure_redirects = 0
		net.ipv4.conf.all.send_redirects = 0
		net.ipv4.conf.default.accept_redirects = 0
		net.ipv4.conf.default.accept_source_route = 0
		net.ipv4.conf.default.log_martians = 1
		net.ipv4.conf.default.rp_filter = 1
		net.ipv4.conf.default.secure_redirects = 0
		net.ipv4.conf.default.send_redirects = 0
		net.ipv4.icmp_echo_ignore_all = 1
		net.ipv4.icmp_echo_ignore_broadcasts = 1
		net.ipv4.icmp_ignore_bogus_error_responses = 1
		net.ipv4.ip_forward = 0
		net.ipv4.ip_local_port_range = 2000 65000
		net.ipv4.tcp_max_syn_backlog = 2048
		net.ipv4.tcp_synack_retries = 2
		net.ipv4.tcp_syncookies = 1
		net.ipv4.tcp_syn_retries = 5
		net.ipv4.tcp_timestamps = 9

		# Disable IPv6
		net.ipv6.conf.all.disable_ipv6 = 1
		net.ipv6.conf.default.disable_ipv6 = 1
		net.ipv6.conf.lo.disable_ipv6 = 1

		# Incase IPv6 is necessary
		net.ipv6.conf.default.router_solicitations = 0
		net.ipv6.conf.default.accept_ra_rtr_pref = 0
		net.ipv6.conf.default.accept_ra_pinfo = 0
		net.ipv6.conf.default.accept_ra_defrtr = 0
		net.ipv6.conf.default.autoconf = 0
		net.ipv6.conf.default.dad_transmits = 0
		net.ipv6.conf.default.max_addresses = 1
		```

	1. Load new sysctl settings

		`$ sysctl -p` or `sysctl --system`










1. Antivirus

	1. Install `clamav`, `chkrootkit`, and `rkhunter`

		`$ apt-get install clamav chkrootkit rkhunter`

	1. Run ClamAV

		```
		$ freshclam
		$ freshclam --help
  		$ clam scan(run from root dir) 
		```

	1. Run chkrootkit

		`$ chkrootkit -l`

	1. Run RKHunter

		```
		$ rkhunter --update
		$ rkhunter --propupd
		$ rkhunter -c --enable all --disable none
		```

	1. Look through `/var/log/rkhunter.log`










1. Audit the System with Lynis

	1. Install

		```
		$ cd /usr/local
		$ git clone https://github.com/CISOfy/lynis
		$ chown -R 0:0 /usr/local/lynis
		```

	1. Audit the system with Lynis

		```
		$ cd /usr/local/lynis
		$ lynis audit system
		```

	1. Look through `/var/log/lynis-report.dat` for warnings and suggestions

		`$ grep -E 'warning|suggestion' | sed -e 's/warning\[\]\=//g' | sed -e 's/suggestion\[\]\=//g'`












1. Configure Auditd

	1. Install

		`$ apt-get install auditd`

	1. Enable

		`$ auditctl -e 1`

	1. Configure with `/etc/audit/auditd.conf`

## Other Checklists

[SANS Hardening the Linux System](https://www.sans.org/media/score/checklists/LinuxCheatsheet_2.pdf)

[Awesome Security Hardening](https://github.com/decalage2/awesome-security-hardening)



## Used Checklists
1. https://github.com/CAMS-CyberPatriot/Linux-Checklist-1
2. https://sites.google.com/view/ahscybersec/home?authuser=0

