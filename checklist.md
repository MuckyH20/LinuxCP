# LinuxCP
# SixSwords Linux Checklist

## Notes
MISC

W theme
^e set colorscheme material-tc

Assume root permissions are needed for most commands. You can use `sudo` or become root with `su`.

I would no longer recommend running `apt-get dist-upgrade` in competition. They may call it intelligent, but it has a bad track record of breaking critical services.

Enable pasting if not already enabled `sudo apt install open-vm-tools open-vm-tools-desktop -y`

So far in this checklist you are mostly adding to text files, but remember there may be things to be removed within. For example, in pam/common-auth in 'auth [success=2 default=ignore] pam_unix.so nullok' nullok allows empty passwords to log in so it must be removed. You have to actually understand these services. STIGS and CIS have baselines. Gotta find which modules are and where they should be.

Take snapshots if things break

Use clean image to baseline, like repos

Use man pages on the fly to figure out where vulns could be hiding. ReadME has hints

grep -R looks in all files in a dir. Ex: grep -r "nc -lvnp 444" to find netcat

avoid guis as cmd is same on distros

Focus on attack surface minimization. Cybersecuity inuition and fundamentals


## Checklist

-
   
remember to restart things to get points, systemctl, lightdm etc



   
           


	1. Check minimum and maximum password ages in `/etc/shadow`

		Use `chage` to change password expiration.

		`$ chage -m $MIN -M $MAX $user`

	1. Script
	```
 	#!/bin/bash

	# Set default inactivity period to 30 days for new users
	useradd -D -f 30

	# Enforce 30-day inactivity for all existing non-system users
	for user in $(awk -F: '{ if ($3 >= 1000) print $1 }' /etc/passwd); do
            chage --inactive 30 "$user"

            # Ensure no user has a password change date in the future
            last_change=$(chage -l "$user" | grep "Last password change" | cut -d: -f2)
            if [[ $(date -d "$last_change" +%s) -gt $(date +%s) ]]; then
                chage -d 0 "$user"
            fi
        done

	# Lock and set non-login shell for system users (UID < 1000)
	for user in $(awk -F: '($3 < 1000) {print $1 }' /etc/passwd); do
    	    if [ "$user" != "root" ]; then
               usermod -L "$user"
               if [ "$user" != "sync" ] && [ "$user" != "shutdown" ] && [ "$user" != "halt" ]; then
                   usermod -s /usr/sbin/nologin "$user"
               fi
            fi
        done

	




		**There also may be unauthorized network shares not under the /home directory**
	1. Files/directories
		```
		sudo rm -f [file]
		sudo rm -rf [directory]
		Apt-mark to see if manually installed or held
		Turn on automatic backup
		```






	1. Verify Repositories

		1. Check apt repository policy

			`$ apt-cache policy`

		```
  		
 	1. Configure unattended upgrades
     		https://wiki.debian.org/UnattendedUpgrades
     		https://help.ubuntu.com/community/AutomaticSecurityUpdates
	THe 10periodic 50 and 100 files in checklist check

           
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

			`service --status-all or systemctl list-units --type=service --state=active  systemctl status to check if start on boot`
			`sudo systemctl disable --now $service`

		BAD STUFF

		`john, nmap, vuze, frostwire, kismet, freeciv, minetest, minetest-server, medusa, hydra, truecrack, ophcrack, nikto, cryptcat, nc, netcat, tightvncserver, x11vnc, nfs, xinetd`

		POSSIBLY BAD STUFF

		`samba, postgresql, sftpd, vsftpd, apache, apache2, ftp, mysql, php, snmp, pop3, icmp, sendmail, dovecot, bind9, nginx`

		MEGA BAD STUFF

		`telnet, rlogind, rshd, rcmd, rexecd, rbootd, rquotad, rstatd, rusersd, rwalld, rexd, fingerd, tftpd, telnet, snmp, netcat, nc`







1. Service & Application Hardening

   
For all:
Risk mitigation:

Network traffic encryption
http vs https
TLS is the standard, ssl is old
Up to date ciphersuites to have up to date encryption(ex. ECDHE-ECDSA-AES128-GCM-SHA256)
Mozilla SSL Generator is good for all this
Be careful as backwards compatibility has to be present, customers with older pcs need to use so dont be too restrictive in that way


Access control
	Authentication
	Scenario dependent
 	Authenetication "schemes"
  		Common: Public-Key: used for employees
    		Passwprd
      			Compares with local password hashes
	 		poor password hygeine and brute force attacks, strict password reqs
    		Kerberos not used in comp but companies use
      		PAM: /etc/pam.d/service
 
 	Root Level Access
		Discourage highly pemissive access completely
  		Thats it

    		Instead elevate using appropriate program command, like sudo in like openssh server ex
   	
  	Anonymous Access
   		Scenario dependent(Something like a file server would want but not openssh)
     		fINE TUNE PERMISSIONS BASED ON USE CASE
       			Public file server should be read only as opposed to read-write, write only
	  	Authentication: password based (for anon users)
     		
   		

   System configuration
   	Daemon privligges
    		Processes are tied to a user
      			Background processes spawned by SystemD = Daemon
	 		inherit all perms -> least permissive user (in.service)
    		Processes are spawned by services
		Overall check systemD service config file for crit service

      
    	Filesystem privligges
     		Only admin should configure server
       			Be aware of parent/child director{ies}/path{s}
	  	Data directory access control
    			"data" directories: databases, file shares(ex webserver public root dirwwwhtml)
     
     	Debug information
      		Errors should not be shown to customers
		Knowing exact software version helps identify vulnerabilities
  			CVES corrsoposding to versions -> known exploits for old software
     	Exteranally, debug as little as possible
      	Internally, log as much as possible
      		

Incident Response:
Logging
	Highest verbosity logging
	usually stored in log{s}/
 	Permissions: superuser + darmon user

  Rules of thumb:
  Externally: reduce attack service
  Internaly:
  	Principle of least privlege
   	Prepare for an incident


Examples:
   Apache
 nginx
PostgreSQL
MySQL
SSH
MSSQL
VNC
LAMP Server (Linux Apache Mysql PHP) and variations
Wordpress
SMB
FTP
DNS
Samba 
Mail

	1. Configure OpenSSH Server in `/etc/ssh/sshd_config(ssh specific key perms if readme asks or crit service)`

   ```

    apt install openssh-server -y
    service ssh enable
    service ssh start
    chown root:root /etc/ssh/sshd_config
    chmod og-rwx /etc/ssh/sshd_config
   	~/.ssh
        -rw-------. 1 fred fred  565 Dec 12  2012 authorized_keys(check inside this file if any unwanted keys are in here)
	-rw-------. 1 fred fred 2590 Dec 12  2012 id_rsa
	-rw-r--r--. 1 fred fred  565 Dec 12  2012 id_rsa.pub
	-rw-------. 1 fred fred   91 Dec 12  2012 known_hosts


    /etc/ssh/sshd_config:
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
        PasswordAuthentication yes/no ??????? depends on read me if asking for key auth only
	PubkeyAuthentication yes/no same as above
        AllowUsers <userlist>
        AllowGroups <grouplist>
        DenyUsers <userlist>
        DenyGroups <grouplist>

    service sshd restart
    sshd -T
    ufw allow 8808
    systemctl reload sshd

    ```

	1. Harden Firefox

  		1. block popups, look for concerning things
		1. 1) Open Firefox's settings
		1. 2) Go to "Privacy & Security"
		1. 3) At the bottom, check "Block dangerous and deceptive content" and all sub-checks
		

	1. Configure apache2 in `/etc/apache2/apache2.conf`

		```
		apt install apache2
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
		/etc/apache2/apache2conf
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
		# $EDITOR httpsd.conf
		<Directory /opt/apache/htdocs>
		Options None
		</Directory>
		<Directory />
		Options -Indexes
		AllowOverride None
		</Directory>
		service apache2 restart
		```
  	1. mySQL
      
      		```
      		apt install mysql-server -y
      		mysql_secure_installation
      		service mysql enable
      		service mysql start
      		/etc/mysql/mysql.conf.d/mysqld.cnf
      		bind-address = 127.0.0.1
      		user = mysql
      		port = 1542
      		local_infile = 0
      		symbolic-links = 0
      		default_password_lifetime = 90
      		service mysql restart
		```
   	1. Postfix
   	   	```
   	        /etc/postfix/main.cf:
		inet_interfaces = loopback-only



1. Remove uneccessary proccesses with
   ```
   ps auxf: 
   sudo kill -9 $PID
   then remove files with rm. Look for exe under the pid dir in the proc dir. It is a symbolic link to the binary.
   If cmdline symb link in /proc pid is suspicious like /bin/nice -lvnp 444, netcat flags look like that so suspicious <- example. 
   status shows ppid, parent process id

   Look for compromised binaries
   grep -r ifconfig.me
   sudo apt reinstall
  

1. Backdoor Detection and Removal

	1. `ss -tulpn`(dont forget sudo). Running as sudo gives process so you can directly find location with which or whereis and kill process and then delete file. Also must check for crontab. Check for crontab first. sudo pkill -f $process name and sudo rm /dir. ![image](https://github.com/user-attachments/assets/d541be11-b607-406b-9dc8-0d865103d414)

    	1. alt commands
        ```
         apt install nmap -y && nmap -sVf -p- 127.0.0.1 && apt purge nmap -y
         lsof -i -n -p
         netstat -tulpn
   

	1. If a port has `127.0.0.1:$port` in its line, that means it's connected to loopback and isn't exposed. Otherwise, there should only be ports which are specified in the readme open (but there probably will be tons more).

	1. For each open port which should be closed

		1. Find the program using the port

			`$ lsof -i $port`
			or
			`ps auxf | grep PID`

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

   		1. .so files are sus. ufw enable will tell you if something is world writable, look in there. usually they have connect in them or socket




1. Check exec lines for debug mode and capability for root privlige for process  in. Generally baseline to see if they are tampered with. User and group may be set to root. usr/lib/systemd/system networkmanager? systemd.unit. Baseline whole of systemD service config.



1. Cron

	1. Check your user's crontabs

		`$ crontab -e`

	1. Check `/etc/cron.*/`, `/etc/crontab`, and `/var/spool/cron/`

	1. Check init files in `/etc/init/` and `/etc/init.d/`

	1. Remove contents of `/etc/rc.local`

		`$ echo "exit 0" > /etc/rc.local`

	1. Check user crontabs

		`$ crontab -u $user -l`

	1. Deny users use of cron jobs

		`$ echo "ALL" >> /etc/cron.deny`

	1. install bum to check start up services

    	1. So gnome has its own kind of autostart for different services and programs. This is located in the ~/.config/autostart directory so deleting this will gain points.




	1. Perms

    	```
  		  sdsdsd
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
		chmod og-rwx /etc/cron.d# systemctl enable cron
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
        ```







1. Kernel Hardening

	1. Edit the `/etc/sysctl.conf` file(might be more)

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


  		alt:

  		/etc/sysctl.conf:
		fs.protected_hardlinks=1
		fs.protected_symlinks=1
		fs.suid_dumpable=0
  		kernel.kptr_restrict=2
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
		/etc/security/limits.conf:
		* hard core 0
		/etc/modprobe.d/CIS.conf:
		install dccp /bin/true
		install sctp /bin/true
		install rds /bin/true
		install tipc /bin/true
		/etc/host.conf:
		order bind,hosts
		multi on
		nospoof on
		/etc/resolv.conf:
		make server 8.8.8.8
		/etc/rc.local:
		exit 0
		```

	1. Load new sysctl settings

		`$ sysctl -p` or `sysctl --system`
	1. Mounting
	```
	mount -o remountcnoexec /dev/shm
	mount -o remount,nosuid /dev/shm1
	mount -o remount,nodev /dev/shm
	/etc/fstab:
	none /run/shm tmpfs defaults,ro 0 0









1. Antivirus

	1. Install `clamav`, `chkrootkit`, and `rkhunter`

		`$ apt-get install clamav chkrootkit rkhunter`

	1. Run ClamAV

		```
		$ freshclam
		$ freshclam --help
  		$ clam scan
  		$ clamscan -r --remove
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

	1. Look at /etc/modules-load.d/ for systemD modules on start up, .ko files like dll. See what it is with modinfo and remove with rmmod.








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
		$ lynis audit system or lynis -c
		```

	1. Look through `/var/log/lynis-report.dat or lynis.log` for warnings and suggestions

		`$ grep -E 'warning|suggestion' | sed -e 's/warning\[\]\=//g' | sed -e 's/suggestion\[\]\=//g'`



1. USB
   ```
        # Stop and disable autofs to prevent automatic filesystem mounting
	service autofs stop
	systemctl disable autofs

	# Blacklist usb-storage to disable USB storage device access
	echo "blacklist usb-storage" | sudo tee /etc/modprobe.d/blacklist-usb-storage.conf
	sudo modprobe -r usb-storage  # Unload if already loaded

	# Install and enable USBGuard for USB access control
	apt install usbguard -y
	systemctl start usbguard
	systemctl enable usbguard









1. Configure Auditd

	1. Install

		`$ apt-get install auditd`

	1. Enable

		`$ auditctl -e 1`

	1. Configure with `/etc/audit/auditd.conf`
```
/etc/audit/audit.rules:
-D
-w / -p rwax -k filesystem_change
-a always,exit -S all
-e 2
/etc/audit/auditd.conf:
max_log_file_action=keep_log
```


Misc:
```
snap refresh
apt install rsyslog -y
systemctl enable rsyslog
/etc/rsyslog.conf:
Remove anything that sends logs to a domain
apt purge xinetd openbsd-inetd inetutils-inetd -y
apt install tcpd -y
apt install apparmor -y
aa-enforce /etc/apparmor.d/*
```



## Other Checklists

[SANS Hardening the Linux System](https://www.sans.org/media/score/checklists/LinuxCheatsheet_2.pdf)

[Awesome Security Hardening](https://github.com/decalage2/awesome-security-hardening)



## Used Checklists
1. https://github.com/Forty-Bot/linux-checklist
2. https://github.com/CAMS-CyberPatriot/Linux-Checklist-1
3. https://sites.google.com/view/ahscybersec/home?authuser=0
4. https://codeberg.org/easw/cyberpatriot/src/branch/main/cyberpatriots/linux_checklist.md/
5. https://github.com/im-Google/Cyberpatriot/tree/main/Linux


