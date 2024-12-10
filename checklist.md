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

if ping not working so cant download anything add nameserver 8.8.8.8
nameserver 1.1.1.1
in /etc/resolv.conf

Path variable 


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
   			$ xapt list --installed | cut -d/ -f1
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













     		


    chown root:root /etc/ssh/sshd_config
    chmod og-rwx /etc/ssh/sshd_config
   	~/.ssh
        -rw-------. 1 fred fred  565 Dec 12  2012 authorized_keys(check inside this file if any unwanted keys are in here)
	-rw-------. 1 fred fred 2590 Dec 12  2012 id_rsa
	-rw-r--r--. 1 fred fred  565 Dec 12  2012 id_rsa.pub
	-rw-------. 1 fred fred   91 Dec 12  2012 known_hosts


    

    ```

	1. Harden Firefox

  		1. block popups, look for concerning things
		1. 1) Open Firefox's settings
		1. 2) Go to "Privacy & Security"
		1. 3) At the bottom, check "Block dangerous and deceptive content" and all sub-checks
		


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


