#!/bin/bash
# 
# Script: supplemental_hardening_rhel7.sh
# Description: RHEL 7 Hardening to STIG
# License: Apache License, Version 2.0
#
#   Absolutely utilized Frank Caviggia of
#   Red Hat Consulting's ssg-suplemental.sh 
#   script as a starting point and made major 
#   changes to large portions of the script.
#   https://github.com/RedHatGov/ssg-el7-kickstart
#
# It is expected that administrators will
# run this script shortly after a server 
# is freshly deployed.  I do not apologies
# for any of the language in comments.  It
# is absolutely necessary if you've ever
# tried making this sort of thing before.

passw=""

echo "beginning hardening"
sleep 5

########################################
# LEGAL BANNER CONFIGURATION
########################################
#BANNER_MESSAGE_TEXT='You are accessing a U.S. Government (USG) Information System (IS) that is \nprovided for USG-authorized use only. By using this IS (which includes any \ndevice attached to this IS), you consent to the following conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for \npurposes including, but not limited to, penetration testing, COMSEC monitoring, \nnetwork operations and defense, personnel misconduct (PM), law enforcement \n(LE), and counterintelligence (CI) investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject \nto routine monitoring, interception, and search, and may be disclosed or used \nfor any USG-authorized purpose.\n\n-This IS includes security measures (e.g., authentication and access controls) \nto protect USG interests -- not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE \nor CI investigative searching or monitoring of the content of privileged \ncommunications, or work product, related to personal representation or services \nby attorneys, psychotherapists, or clergy, and their assistants. Such \ncommunications and work product are private and confidential. See User \nAgreement for details.\n\n'
login_banner_text="^(You[\s\n]+are[\s\n]+accessing[\s\n]+a[\s\n]+U.S.[\s\n]+Government[\s\n]+\(USG\)[\s\n]+Information[\s\n]+System[\s\n]+\(IS\)[\s\n]+that[\s\n]+is[\s\n]+provided[\s\n]+for[\s\n]+USG-authorized[\s\n]+use[\s\n]+only.[\s\n]*By[\s\n]+using[\s\n]+this[\s\n]+IS[\s\n]+\(which[\s\n]+includes[\s\n]+any[\s\n]+device[\s\n]+attached[\s\n]+to[\s\n]+this[\s\n]+IS\),[\s\n]+you[\s\n]+consent[\s\n]+to[\s\n]+the[\s\n]+following[\s\n]+conditions\:[\s\n]*-[\s\n]*The[\s\n]+USG[\s\n]+routinely[\s\n]+intercepts[\s\n]+and[\s\n]+monitors[\s\n]+communications[\s\n]+on[\s\n]+this[\s\n]+IS[\s\n]+for[\s\n]+purposes[\s\n]+including,[\s\n]+but[\s\n]+not[\s\n]+limited[\s\n]+to,[\s\n]+penetration[\s\n]+testing,[\s\n]+COMSEC[\s\n]+monitoring,[\s\n]+network[\s\n]+operations[\s\n]+and[\s\n]+defense,[\s\n]+personnel[\s\n]+misconduct[\s\n]+\(PM\),[\s\n]+law[\s\n]+enforcement[\s\n]+\(LE\),[\s\n]+and[\s\n]+counterintelligence[\s\n]+\(CI\)[\s\n]+investigations.[\s\n]*-[\s\n]*At[\s\n]+any[\s\n]+time,[\s\n]+the[\s\n]+USG[\s\n]+may[\s\n]+inspect[\s\n]+and[\s\n]+seize[\s\n]+data[\s\n]+stored[\s\n]+on[\s\n]+this[\s\n]+IS.[\s\n]*-[\s\n]*Communications[\s\n]+using,[\s\n]+or[\s\n]+data[\s\n]+stored[\s\n]+on,[\s\n]+this[\s\n]+IS[\s\n]+are[\s\n]+not[\s\n]+private,[\s\n]+are[\s\n]+subject[\s\n]+to[\s\n]+routine[\s\n]+monitoring,[\s\n]+interception,[\s\n]+and[\s\n]+search,[\s\n]+and[\s\n]+may[\s\n]+be[\s\n]+disclosed[\s\n]+or[\s\n]+used[\s\n]+for[\s\n]+any[\s\n]+USG-authorized[\s\n]+purpose.[\s\n]*-[\s\n]*This[\s\n]+IS[\s\n]+includes[\s\n]+security[\s\n]+measures[\s\n]+\(e.g.,[\s\n]+authentication[\s\n]+and[\s\n]+access[\s\n]+controls\)[\s\n]+to[\s\n]+protect[\s\n]+USG[\s\n]+interests--not[\s\n]+for[\s\n]+your[\s\n]+personal[\s\n]+benefit[\s\n]+or[\s\n]+privacy.[\s\n]*-[\s\n]*Notwithstanding[\s\n]+the[\s\n]+above,[\s\n]+using[\s\n]+this[\s\n]+IS[\s\n]+does[\s\n]+not[\s\n]+constitute[\s\n]+consent[\s\n]+to[\s\n]+PM,[\s\n]+LE[\s\n]+or[\s\n]+CI[\s\n]+investigative[\s\n]+searching[\s\n]+or[\s\n]+monitoring[\s\n]+of[\s\n]+the[\s\n]+content[\s\n]+of[\s\n]+privileged[\s\n]+communications,[\s\n]+or[\s\n]+work[\s\n]+product,[\s\n]+related[\s\n]+to[\s\n]+personal[\s\n]+representation[\s\n]+or[\s\n]+services[\s\n]+by[\s\n]+attorneys,[\s\n]+psychotherapists,[\s\n]+or[\s\n]+clergy,[\s\n]+and[\s\n]+their[\s\n]+assistants.[\s\n]+Such[\s\n]+communications[\s\n]+and[\s\n]+work[\s\n]+product[\s\n]+are[\s\n]+private[\s\n]+and[\s\n]+confidential.[\s\n]+See[\s\n]+User[\s\n]+Agreement[\s\n]+for[\s\n]+details.|I\'ve[\s\n]+read[\s\n]+\&[\s\n]+consent[\s\n]+to[\s\n]+terms[\s\n]+in[\s\n]+IS[\s\n]+user[\s\n]+agreem\'t.)$"

# There was a regular-expression matching various banners, needs to be expanded
# When there are multiple banners in login_banner_text, the first banner should be the one for RHEL7
expanded=$(echo "$login_banner_text" | sed 's/\^(\(.*\)|.*$/\1/g;s/\[\\s\\n\][+*]/ /g;s/\\//g;s/[^-]- /\n\n-/g')
formatted=$(echo "$expanded" | fold -sw 80)

cat <<EOF >/etc/issue
$formatted
EOF

printf "\n" >> /etc/issue

########################################
# DISA STIG PAM Configurations
########################################
cat <<EOF > /etc/pam.d/system-auth-local
#%PAM-1.0
auth required pam_env.so
auth required pam_lastlog.so inactive=35
auth sufficient pam_sss.so forward_pass
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth sufficient pam_unix.so use_first_pass
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth sufficient pam_faillock.so authsucc audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth requisite pam_succeed_if.so uid >= 1000 quiet
auth required pam_deny.so

account required pam_faillock.so
account required pam_unix.so
account required pam_lastlog.so inactive=35
account sufficient pam_localuser.so
account sufficient pam_succeed_if.so uid < 1000 quiet
account required pam_permit.so

# Password Quality now set in /etc/security/pwquality.conf
password required pam_pwquality.so retry=3
password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=24
password required pam_deny.so

session required pam_lastlog.so showfailed
session required pam_limits.so
-session optional pam_systemd.so
session optional  pam_mkhomedir.so umask=0077
session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session required pam_unix.so
EOF
ln -sf /etc/pam.d/system-auth-local /etc/pam.d/system-auth
cp -f /etc/pam.d/system-auth-local /etc/pam.d/system-auth-ac

cat <<EOF > /etc/pam.d/password-auth-local
#%PAM-1.0
auth required pam_env.so
auth required pam_lastlog.so inactive=35
auth sufficient pam_sss.so forward_pass
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth sufficient pam_unix.so use_first_pass
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth sufficient pam_faillock.so authsucc audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth requisite pam_succeed_if.so uid >= 1000 quiet
auth required pam_deny.so

account required pam_faillock.so
account required pam_unix.so
account required pam_lastlog.so inactive=35
account sufficient pam_localuser.so
account sufficient pam_succeed_if.so uid < 1000 quiet
account required pam_permit.so

# Password Quality now set in /etc/security/pwquality.conf
password required pam_pwquality.so retry=3
password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=24
password required pam_deny.so

session required pam_lastlog.so showfailed
session optional pam_keyinit.so revoke
session required pam_limits.so
-session optional pam_systemd.so
session optional  pam_mkhomedir.so umask=0077
session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session required pam_unix.so
EOF
ln -sf /etc/pam.d/password-auth-local /etc/pam.d/password-auth
cp -f /etc/pam.d/password-auth-local /etc/pam.d/password-auth-ac
sleep 5
cat <<EOF > /etc/security/pwquality.conf
# Configuration for systemwide password quality limits
# Defaults:
#
# Number of characters in the new password that must not be present in the
# old password.
# difok = 5
difok = 15
#
# Minimum acceptable size for the new password (plus one if
# credits are not disabled which is the default). (See pam_cracklib manual.)
# Cannot be set to lower value than 6.
# minlen = 9
minlen = 15
#
# The maximum credit for having digits in the new password. If less than 0
# it is the minimum number of digits in the new password.
# dcredit = 1
dcredit = -1
#
# The maximum credit for having uppercase characters in the new password.
# If less than 0 it is the minimum number of uppercase characters in the new
# password.
# ucredit = 1
ucredit = -1
#
# The maximum credit for having lowercase characters in the new password.
# If less than 0 it is the minimum number of lowercase characters in the new
# password.
# lcredit = 1
lcredit = -1
#
# The maximum credit for having other characters in the new password.
# If less than 0 it is the minimum number of other characters in the new
# password.
# ocredit = 1
ocredit = -1
#
# The minimum number of required classes of characters for the new
# password (digits, uppercase, lowercase, others).
minclass = 4
#
# The maximum number of allowed consecutive same characters in the new password.
# The check is disabled if the value is 0.
maxrepeat = 2
#
# The maximum number of allowed consecutive characters of the same class in the
# new password.
# The check is disabled if the value is 0.
maxclassrepeat = 2
#
# Whether to check for the words from the passwd entry GECOS string of the user.
# The check is enabled if the value is not 0.
# gecoscheck = 0
#
# Path to the cracklib dictionaries. Default is to use the cracklib default.
# dictpath =
EOF

echo -e "FAIL_DELAY\t4" >> /etc/login.defs
echo -e "CREATE_HOME\tyes" >> /etc/login.defs
sed -i 's/ENCRYPT_METHOD.*/ENCRYPT_METHOD\tSHA512/g' /etc/login.defs
sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS\t60/g' /etc/login.defs
sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/g' /etc/login.defs


sleep 5
########################################
# STIG Audit Configuration
########################################
cat <<EOF > /etc/audit/rules.d/audit.rules
# DISA STIG Audit Rules
## Add keys to the audit rules below using the -k option to allow for more 
## organized and quicker searches with the ausearch tool.  See auditctl(8) 
## and ausearch(8) for more information.

# Remove any existing rules
-D

# Increase kernel buffer size
-b 16384

# Failure of auditd causes a kernel panic
-f 2

###########################
## DISA STIG Audit Rules ##
###########################

# Watch syslog configuration
-w /etc/rsyslog.conf
-w /etc/rsyslog.d/

# Watch PAM and authentication configuration
-w /etc/pam.d/
-w /etc/nsswitch.conf

# Watch system log files
-w /var/log/messages
-w /var/log/audit/audit.log
-w /var/log/audit/audit[1-4].log

# Watch audit configuration files
-w /etc/audit/auditd.conf -p wa
-w /etc/audit/audit.rules -p wa

# Watch login configuration
-w /etc/login.defs
-w /etc/securetty
-w /etc/resolv.conf

# Watch cron and at
-w /etc/at.allow
-w /etc/at.deny
-w /var/spool/at/
-w /etc/crontab
-w /etc/anacrontab
-w /etc/cron.allow
-w /etc/cron.deny
-w /etc/cron.d/
-w /etc/cron.hourly/
-w /etc/cron.weekly/
-w /etc/cron.monthly/

# Watch shell configuration
-w /etc/profile.d/
-w /etc/profile
-w /etc/shells
-w /etc/bashrc
-w /etc/csh.cshrc
-w /etc/csh.login

# Watch kernel configuration
-w /etc/sysctl.conf
-w /etc/modprobe.conf

# Watch linked libraries
-w /etc/ld.so.conf -p wa
-w /etc/ld.so.conf.d/ -p wa

# Watch init configuration
-w /etc/rc.d/init.d/
-w /etc/sysconfig/
-w /etc/inittab -p wa
-w /etc/rc.local
-w /usr/lib/systemd/
-w /etc/systemd/

# Watch filesystem and NFS exports
-w /etc/fstab
-w /etc/exports

# Watch xinetd configuration
-w /etc/xinetd.conf
-w /etc/xinetd.d/

# Watch Grub2 configuration
-w /etc/grub2.cfg
-w /etc/grub.d/

# Watch TCP_WRAPPERS configuration
-w /etc/hosts.allow
-w /etc/hosts.deny

# Watch sshd configuration
-w /etc/ssh/sshd_config

# Audit system events
-a always,exit -F arch=b32 -S acct -S reboot -S sched_setparam -S sched_setscheduler -S setrlimit -S swapon 
-a always,exit -F arch=b64 -S acct -S reboot -S sched_setparam -S sched_setscheduler -S setrlimit -S swapon 

# Audit any link creation
-a always,exit -F arch=b32 -S link -S symlink
-a always,exit -F arch=b64 -S link -S symlink

##############################
## NIST 800-53 Requirements ##
##############################

#2.6.2.4.1 Records Events that Modify Date and Time Information
-a always,exit -F arch=b32 -S adjtimex -S stime -S settimeofday -S clock_settime -k time-change
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

#2.6.2.4.2 Record Events that Modify User/Group Information
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

#2.6.2.4.3 Record Events that Modify the Systems Network Environment
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k audit_network_modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications
-w /etc/issue -p wa -k audit_network_modifications
-w /etc/issue.net -p wa -k audit_network_modifications
-w /etc/hosts -p wa -k audit_network_modifications
-w /etc/sysconfig/network -p wa -k audit_network_modifications

#2.6.2.4.4 Record Events that Modify the System Mandatory Access Controls
-w /etc/selinux/ -p wa -k MAC-policy

#2.6.2.4.5 Ensure auditd Collects Logon and Logout Events
-w /var/run/faillock -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

#2.6.2.4.6 Ensure auditd Collects Process and Session Initiation Information
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

#2.6.2.4.12 Ensure auditd Collects System Administrator Actions
-w /etc/sudoers -p wa -k actions

#2.6.2.4.13 Make the auditd Configuration Immutable
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-w /usr/sbin/insmod -p x -k modules
-w /usr/sbin/rmmod -p x -k modules
-w /usr/sbin/modprobe -p x -k modules


# Ignore all the anonymous events. Often tagged on every rule, but ignoring 
# up front should improve processing time
-a exit,never -F auid=4294967295
# Ignore system services
-a exit,never -F auid<1000
# Removal of things is baaaaad?
-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=4294967295 -F key=delete
-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=4294967295 -F key=delete
-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=4294967295 -F key=delete
-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=4294967295 -F key=delete
-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=4294967295 -F key=delete
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -F key=export

-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=4294967295 -F key=delete
-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=4294967295 -F key=delete
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=4294967295 -F key=delete
-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=4294967295 -F key=delete
-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=4294967295 -F key=delete
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -F key=export

#2.6.2.4.7 Ensure auditd Collects Discretionary Access Control Permission Modification Events
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -kperm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -k perm_mod
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -k perm_mod
-a always,exit -F arch=b64 -S chmod  -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

#2.6.2.4.8 Ensure auditd Collects Unauthorized Access Attempts to Files (unsuccessful)
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -k access
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

#2.6.2.4.9 Ensure auditd Collects Information on the Use of Privileged Commands
-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged-priv_change
-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged-priv_change
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged-priv_change
-a always,exit -F path=/usr/sbin/restorecon -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged-priv_change
-a always,exit -F path=/usr/bin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged


EOF
# Find all privileged commands and monitor them
for fs in $(awk '($3 ~ /(ext[234])|(xfs)/) {print $2}' /proc/mounts) ; do
	find $fs -xdev -type f -perm -4000 -o -type f -perm -2000| awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged" }' >> /etc/audit/rules.d/audit.rules
done
cat <<EOF >> /etc/audit/rules.d/audit.rules

#2.6.2.4.10 Ensure auditd Collects Information on Exporting to Media (successful)
-a always,exit -F arch=b32 -S mount -k export
-a always,exit -F arch=b64 -S mount -k export

#2.6.2.4.11 Ensure auditd Collects Files Deletion Events by User (successful and unsuccessful)
-a always,exit -F arch=b32 -S unlink -S rmdir -S unlinkat -S rename -S renameat -k delete
-a always,exit -F arch=b64 -S unlink -S rmdir -S unlinkat -S rename -S renameat -k delete

#2.6.2.4.14 Make the auditd Configuration Immutable
-e 2
EOF
cp -f /etc/audit/rules.d/audit.rules /etc/audit/audit.rules

cat << EOF > /etc/audit/auditd.conf
#
# This file controls the configuration of the audit daemon
#

log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file = 6 
max_log_file_action = ROTATE
space_left = 1000
space_left_action = email
action_mail_acct = root
admin_space_left = 500
admin_space_left_action = single
disk_full_action = syslog
disk_error_action = syslog
use_libwrap = yes
##tcp_listen_port = 
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
EOF

########################################
# Additional Fixes from SCAP Scans
#######################################
echo "clean_requirements_on_remove=1" >> /etc/yum.conf
echo "localpkg_gpgcheck=1" >> /etc/yum.conf
echo "repo_gpgcheck=1" >> /etc/yum.conf
echo '0 5 * * * /usr/sbin/aide  --check | /bin/mail -s "$(hostname) - AIDE Integrity Check" root@localhost' >> /var/spool/cron/root
sed -i 's/INACTIVE=.*/INACTIVE=0/g' /etc/default/useradd


#######################################
# AIDE requires ACLs and shit
#######################################

aide_conf="/etc/aide.conf"
forbidden_hashes=(sha1 rmd160 sha256 whirlpool tiger haval gost crc32)
groups=$(grep "^[A-Z]\+" $aide_conf | cut -f1 -d ' ' | tr -d ' ' | sort -u)

for group in $groups
do
  config=$(grep "^$group\s*=" $aide_conf | cut -f2 -d '=' | tr -d ' ')
  if ! [[ $config = *sha512* ]]
    then
	  config=$config"+sha512"
  fi
  for hash in ${forbidden_hashes[@]}; do
    config=$(echo $config | sed "s/$hash//")
  done
  config=$(echo $config | sed "s/^\+*//")
  config=$(echo $config | sed "s/\+\++/+/")
  config=$(echo $config | sed "s/\+$//")
  sed -i "s/^$group\s*=.*/$group = $config/g" $aide_conf
  if ! [[ $config = *acl* ]]; then
    if [[ -z $config ]]; then
      config="acl"
    else
      config=$config"+acl"
    fi
  fi
  sed -i "s/^$group\s*=.*/$group = $config/g" $aide_conf
  if ! [[ $config = *xattrs* ]]; then
	 if [[ -z $config ]]; then
	   config="xattrs"
	 else
	   config=$config"+xattrs"
	 fi
  fi
  sed -i "s/^$group\s*=.*/$group = $config/g" $aide_conf
done

########################################
# RSYSLOG data to Logger
########################################
cat << EOF >> /etc/rsyslog.conf
*.*             @@logger.chs.spawar.navy.mil:514
EOF


########################################
# Set Max Logins
########################################
echo "*	hard	maxlogins	10" >> /etc/security/limits.conf
sed -i 's/crypt_style =.*/crypt_style = sha512/g' /etc/libuser.conf


########################################
# Fix cron.allow
########################################
echo "root" > /etc/cron.allow
chmod 400 /etc/cron.allow
chown root:root /etc/cron.allow


########################################
# Make SELinux Configuration Immutable
########################################
chattr +i /etc/selinux/config


########################################
# Disable Control-Alt-Delete
########################################
ln -sf /dev/null /etc/systemd/system/ctrl-alt-del.target


########################################
# No Root Login to Console (Use admin)
########################################
cat /dev/null > /etc/securetty

########################################
# Disable Interactive Shell (Timeout)
########################################
cat <<EOF > /etc/profile.d/autologout.sh
#!/bin/sh
TMOUT=900
export TMOUT
readonly TMOUT
EOF
cat <<EOF > /etc/profile.d/autologout.csh
#!/bin/csh
set autologout=15
set -r autologout
EOF
chown root:root /etc/profile.d/autologout.sh
chown root:root /etc/profile.d/autologout.csh
chmod 755 /etc/profile.d/autologout.sh
chmod 755 /etc/profile.d/autologout.csh


#########################################
# Set Shell UMASK Setting (027)
########################################
cat <<EOF > /etc/profile.d/umask.sh
#!/bin/sh

# Non-Privileged Users get 027
# Privileged Users get 027
if [[ \$EUID -ne 0 ]]; then
	umask 027
else
	umask 027
fi
EOF
cat <<EOF > /etc/profile.d/umask.csh
#!/bin/csh
umask 027
EOF
chown root:root /etc/profile.d/umask.sh
chown root:root /etc/profile.d/umask.csh
chmod 555 /etc/profile.d/umask.sh
chmod 555 /etc/profile.d/umask.csh


########################################
# Vlock Alias (Cosole Screen Lock)
########################################
cat <<EOF > /etc/profile.d/vlock-alias.sh
#!/bin/sh
alias vlock='clear;vlock -a'
EOF
cat <<EOF > /etc/profile.d/vlock-alias.csh
#!/bin/csh
alias vlock 'clear;vlock -a'
EOF
chown root:root /etc/profile.d/vlock-alias.sh
chown root:root /etc/profile.d/vlock-alias.csh
chmod 755 /etc/profile.d/vlock-alias.sh
chmod 755 /etc/profile.d/vlock-alias.csh


########################################
# Wheel Group Require (sudo)
########################################
sed -i -re '/pam_wheel.so use_uid/s/^#//' /etc/pam.d/su
sed -i 's/^#\s*\(%wheel\s*ALL=(ALL)\s*ALL\)/\1/' /etc/sudoers
echo -e "\n## Set timeout for authentication (5 Minutes)\nDefaults:ALL timestamp_timeout=5\n" >> /etc/sudoers
echo -e "\n## Add SITC Staff Group\n%unix-staff\tALL=(ALL)\tALL\n" >> /etc/sudoers


########################################
# Set Removeable Media to noexec
#   CCE-27196-5
########################################
for DEVICE in $(/bin/lsblk | grep sr | awk '{ print $1 }'); do
	mkdir -p /mnt/$DEVICE
	echo -e "/dev/$DEVICE\t\t/mnt/$DEVICE\t\tiso9660\tdefaults,ro,noexec,noauto,nosuid,nodev\t0 0" >> /etc/fstab
done
for DEVICE in $(cd /dev;ls *cd* *dvd*); do
	mkdir -p /mnt/$DEVICE
	echo -e "/dev/$DEVICE\t\t/mnt/$DEVICE\t\tiso9660\tdefaults,ro,noexec,noauto,nosuid,nodev\t0 0" >> /etc/fstab
done


########################################
# SSHD Hardening
########################################
sed -i '/Ciphers.*/d' /etc/ssh/sshd_config
sed -i '/MACs.*/d' /etc/ssh/sshd_config
sed -i '/Protocol.*/d' /etc/ssh/sshd_config
echo "Protocol 2" >> /etc/ssh/sshd_config
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config
echo "MACs hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
echo "PrintLastLog yes" >> /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
echo "AllowGroups sshusers wheel unix-staff root" >> /etc/ssh/sshd_config
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
echo "Banner /etc/issue" >> /etc/ssh/sshd_config
echo "RhostsRSAAuthentication no" >> /etc/ssh/sshd_config
#echo "GSSAPIAuthentication yes" >> /etc/ssh/sshd_config	# Enable these two
#echo "KerberosAuthentication no" >> /etc/ssh/sshd_config	# for KBT login
echo "IgnoreUserKnownHosts yes" >> /etc/ssh/sshd_config
echo "StrictModes yes" >> /etc/ssh/sshd_config
echo "Compression delayed" >> /etc/ssh/sshd_config
echo "UsePrivilegeSeparation sandbox" >> /etc/ssh/sshd_config
echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config


if [ $(grep -c sshusers /etc/group) -eq 0 ]; then
	/usr/sbin/groupadd sshusers &> /dev/null
fi


########################################
# TCP_WRAPPERS
########################################
cat <<EOF >> /etc/hosts.allow
# LOCALHOST (ALL TRAFFIC ALLOWED) DO NOT REMOVE FOLLOWING LINE
ALL: 127.0.0.1 [::1]
# Allow SSH (you can limit this further using IP addresses - e.g. 192.168.0.*)
sshd: ALL
EOF
cat <<EOF >> /etc/hosts.deny
# Deny All by Default
ALL: ALL
EOF


########################################
# Filesystem Attributes
#  CCE-26499-4,CCE-26720-3,CCE-26762-5,
#  CCE-26778-1,CCE-26622-1,CCE-26486-1.
#  CCE-27196-5
########################################
FSTAB=/etc/fstab
SED=`which sed`

if [ $(grep " \/sys " ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
	MNT_OPTS=$(grep " \/sys " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/sys.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/boot " ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
	MNT_OPTS=$(grep " \/boot " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/boot.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/usr " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/usr " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/usr .*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/home " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/home " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/home .*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/export\/home " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/export\/home " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/export\/home .*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/usr\/local " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/usr\/local " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/usr\/local.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/dev\/shm " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/dev\/shm " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/dev\/shm.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/tmp " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/tmp " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/tmp.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/tmp " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/tmp " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/tmp.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/log " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/tmp " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/tmp.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/log\/audit " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/log\/audit " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/log\/audit.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/www " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/wwww " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/www.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/opt " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/opt " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/opt.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
echo -e "tmpfs\t\t\t/dev/shm\t\ttmpfs\tnoexec,nosuid,nodev\t\t0 0" >> /etc/fstab


########################################
# File Ownership 
########################################
find / -nouser -print | xargs chown root
find / -nogroup -print | xargs chown :root
cat <<EOF > /etc/cron.daily/unowned_files
#!/bin/sh
# Fix user and group ownership of files without user
find / -nouser -print | xargs chown root
find / -nogroup -print | xargs chown :root
EOF
chown root:root /etc/cron.daily/unowned_files
chmod 0700 /etc/cron.daily/unowned_files

########################################
# USGCB Blacklist
########################################
if [ -e /etc/modprobe.d/usgcb-blacklist.conf ]; then
	rm -f /etc/modprobe.d/usgcb-blacklist.conf
fi
touch /etc/modprobe.d/usgcb-blacklist.conf
chmod 0644 /etc/modprobe.d/usgcb-blacklist.conf
chcon 'system_u:object_r:modules_conf_t:s0' /etc/modprobe.d/usgcb-blacklist.conf

cat <<EOF > /etc/modprobe.d/usgcb-blacklist.conf
# Disable Bluetooth
install bluetooth /bin/true
# Disable AppleTalk
install appletalk /bin/true
# NSA Recommendation: Disable mounting USB Mass Storage
install usb-storage /bin/true
# Disable mounting of cramfs CCE-14089-7
install cramfs /bin/true
# Disable mounting of freevxfs CCE-14457-6
install freevxfs /bin/true
# Disable mounting of hfs CCE-15087-0
install hfs /bin/true
# Disable mounting of hfsplus CCE-14093-9
install hfsplus /bin/true
# Disable mounting of jffs2 CCE-14853-6
install jffs2 /bin/true
# Disable mounting of squashfs CCE-14118-4
install squashfs /bin/true
# Disable mounting of udf CCE-14871-8
install udf /bin/true
# CCE-14268-7
install dccp /bin/true
# CCE-14235-5
install sctp /bin/true
#i CCE-14027-7
install rds /bin/true
# CCE-14911-2
install tipc /bin/true
# CCE-14948-4 (row 176)
install net-pf-31 /bin/true
EOF


########################################
# Ensure CHONYD has Maxpoll set
########################################
sed -i 's/^server\(.*\)/server\0\ maxpoll\ 10/g' /etc/chrony.conf


########################################
# GNOME 3 Lockdowns
########################################
if [ -x /bin/gsettings ]; then
	cat << EOF > /etc/gdm/custom.conf
[daemon]
TimedLoginEnable=false
AutomaticLoginEnable=false
EOF
	cat << EOF > /etc/dconf/db/gdm.d/99-gnome-hardening
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text="${BANNER_MESSAGE_TEXT}"
disable-user-list=true
disable-restart-buttons=true

[org/gnome/desktop/lockdown]
user-administration-disabled=true
disable-user-switching=true

[org/gnome/desktop/media-handling]
automount=false
automount-open=false
autorun-never=true

[org/gnome/desktop/notifications] 
show-in-lock-screen=false

[org/gnome/desktop/privacy]
remove-old-temp-files=true
remove-old-trash-files=true
old-files-age=7

[org/gnome/desktop/interface]
clock-format="12h"

[org/gnome/desktop/screensaver]
user-switch-enabled=false

[org/gnome/desktop/session]
idle-delay=900

[org/gnome/desktop/thumbnailers]
disable-all=true

[org/gnome/nm-applet]
disable-wifi-create=true
EOF
	cat << EOF > /etc/dconf/db/gdm.d/locks/99-gnome-hardening
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
/org/gnome/login-screen/disable-user-list
/org/gnome/login-screen/disable-restart-buttons
/org/gnome/desktop/lockdown/user-administration-disabled
/org/gnome/desktop/lockdown/disable-user-switching
/org/gnome/desktop/media-handling/automount
/org/gnome/desktop/media-handling/automount-open
/org/gnome/desktop/media-handling/autorun-never
/org/gnome/desktop/notifications/show-in-lock-screen
/org/gnome/desktop/privacy/remove-old-temp-files
/org/gnome/desktop/privacy/remove-old-trash-files
/org/gnome/desktop/privacy/old-files-age
/org/gnome/desktop/screensaver/user-switch-enabled
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/thumbnailers/disable-all
/org/gnome/nm-applet/disable-wifi-create
EOF
cat << EOF > /usr/share/glib-2.0/schemas/99-custom-settings.gschema.override
[org.gnome.login-screen]
banner-message-enable=true
banner-message-text="${BANNER_MESSAGE_TEXT}"
disable-user-list=true
disable-restart-buttons=true

[org.gnome.desktop.lockdown]
user-administration-disabled=true
disable-user-switching=true

[org.gnome.desktop.media-handling]
automount=false
automount-open=false
autorun-never=true

[org.gnome.desktop.notifications] 
show-in-lock-screen=false

[org.gnome.desktop.privacy]
remove-old-temp-files=true
remove-old-trash-files=true
old-files-age=7

[org.gnome.desktop.interface]
clock-format="12h"

[org.gnome.desktop.screensaver]
user-switch-enabled=false

[org.gnome.desktop.session]
idle-delay=900

[org.gnome.desktop.thumbnailers]
disable-all=true

[org.gnome.nm-applet]
disable-wifi-create=true
EOF
cp /etc/dconf/db/gdm.d/locks/99-gnome-hardening /etc/dconf/db/local.d/locks/99-gnome-hardening
/bin/glib-compile-schemas /usr/share/glib-2.0/schemas/
/bin/dconf update
fi

########################################
# Kernel - Randomize Memory Space
# CCE-27127-0, SC-30(2), 1.6.1
########################################
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

########################################
# Kernel - Accept Source Routed Packets
# AC-4, 366, SRG-OS-000480-GPOS-00227
########################################
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf

########################################
# Kernel - Disable TCP Timestamps
#######################################
echo "net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf

#######################################
# Kernel - Disable Redirects
#######################################
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf

#######################################
# Kernel - Disable ICMP Broadcasts
#######################################
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf

#######################################
# Kernel - Disable Syncookies
#######################################
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

########################################
# Disable SystemD Date Service 
# Use (chrony or ntpd)
########################################
timedatectl set-ntp false

########################################
# Disable Kernel Dump Service
########################################
#systemctl disable kdump.service
#systemctl mask kdump.service
systemctl disable kdump
firewall-offline-cmd --set-default-zone=drop
firewall-offline-cmd --zone=drop --add-service=ssh 
firewall-offline-cmd --zone=drop --add-port=22/tcp


########################################
# Lock Root Account
########################################
#passwd -l root
#echo "" > /etc/securetty
# you'll want to make an emergency account
# before you uncomment this line 


########################################
# Fuck GRUB2 Hardening
########################################
passv="2"
# leave this shit alone

if [[ -z $passw ]]; then 
  while [[ $passw != $passv ]]; do
    read -sp "Enter Password: " passw ; printf "\n"
    read -sp "Re-enter Password: " passv; printf "\n"
    printf "\n"
  done
fi
passentry=$(printf "%s\n%s\n" "$passw" "$passw" | grub2-mkpasswd-pbkdf2 | awk '/grub.pbkdf/{print$NF}')
cat << EOD > /etc/grub.d/01_users
#!/bin/sh -e
cat << EOF
if [ -f \${prefix}/user.cfg ]; then
  source \${prefix}/user.cfg
  if [ -n "\${GRUB2_PASSWORD}" ]; then
    set superusers="mr.gency"
    export superusers
    password_pbkdf2 mr.gency $passentry
  fi
fi
EOF
EOD

grub2-mkconfig -o /boot/grub2/grub.cfg
echo "finished applying hardening"; printf "\n"
sleep 3
