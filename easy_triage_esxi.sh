#!/bin/sh

# By Maxim Suhanov, CICADA8
# License: GPLv3 (see 'License.txt')

TOOL_VERSION='20260117'

echo 'Running easy_triage_esxi...'
echo "  version: $TOOL_VERSION"

echo "$TOOL_VERSION" > triage_results.txt
date >> triage_results.txt
echo '===== VERSION:' >> triage_results.txt
esxcli system version get >> triage_results.txt
echo '===== BOOT TIME:' >> triage_results.txt
cat /var/run/bootTime >> triage_results.txt
echo '===== UPTIME:' >> triage_results.txt
uptime >> triage_results.txt
echo '===== SYSLOG CONFIG:' >> triage_results.txt
esxcli system syslog config get >> triage_results.txt
echo '===== SNMP:' >> triage_results.txt
esxcli system snmp get >> triage_results.txt
echo '===== ACCOUNT LIST:' >> triage_results.txt
esxcli system account list >> triage_results.txt
echo '===== LOGGED ON USERS:' >> triage_results.txt
w >> triage_results.txt
echo '---' >> triage_results.txt
who >> triage_results.txt
echo '===== PERMISSION LIST:' >> triage_results.txt
esxcli system permission list >> triage_results.txt
echo '===== NETWORK INTERFACES:' >> triage_results.txt
esxcli network ip interface list >> triage_results.txt
echo '======= IPv4:' >> triage_results.txt
esxcli network ip interface ipv4 get >> triage_results.txt
echo '======= IPv6:' >> triage_results.txt
esxcli network ip interface ipv6 get >> triage_results.txt
echo '===== BOOT:' >> triage_results.txt
esxcli hardware trustedboot get >> triage_results.txt
echo '===== VM LIST:' >> triage_results.txt
esxcli vm process list >> triage_results.txt
echo '===== FILE SYSTEMS:' >> triage_results.txt
esxcli storage filesystem list >> triage_results.txt
echo '===== DISK USAGE:' >> triage_results.txt
df -h >> triage_results.txt
echo '===== CORE DUMPS CONFIGURED:' >> triage_results.txt
esxcli system coredump file get >> triage_results.txt
echo '===== EXECUTION OF 3RD-PARTY BINARIES:' >> triage_results.txt
esxcli system settings kernel list -o execInstalledOnly >> triage_results.txt
echo '===== HOSTNAME:' >> triage_results.txt
hostname  >> triage_results.txt
echo '===== PROCESS LIST' >> triage_results.txt
ps -P -c -g -i -j -s -t -v -Z >> triage_results.txt
echo '===== PROCESS TREE' >> triage_results.txt
ps -J -c -v >> triage_results.txt
echo '===== PROCESS LIST #2' >> triage_results.txt
esxcli system process list >> triage_results.txt
echo '===== PROCESS LIST #3' >> triage_results.txt
ps -P -v >> triage_results.txt
echo '===== NETSTAT:' >> triage_results.txt
esxcli network ip connection list >> triage_results.txt
echo '===== ARP:' >> triage_results.txt
esxcli network ip neighbor list >> triage_results.txt
echo '===== LSOF:' >> triage_results.txt
lsof >> triage_results.txt
echo '===== DMESG:' >> triage_results.txt
dmesg >> triage_results.txt
echo '===== SHELL HISTORY:' >> triage_results.txt
cat /.ash_history >> triage_results.txt
echo '===== PYTHON HISTORY:' >> triage_results.txt
cat /.python_history >> triage_results.txt 2>/dev/null
echo '===== CRONTAB:' >> triage_results.txt
cat /var/spool/cron/crontabs/root >> triage_results.txt
echo '===== LOCAL.SH:' >> triage_results.txt
cat /etc/rc.local.d/local.sh >> triage_results.txt
echo '===== LOCAL.TGZ:' >> triage_results.txt
tar -tvf /local.tgz >> triage_results.txt
echo '===== STATE.TGZ:' >> triage_results.txt
stat /bootbank/state.tgz >> triage_results.txt
tar -tvf /bootbank/state.tgz >> triage_results.txt
echo '===== TIMELINE (/ + /tmp/ + /var/tmp/ + /dev/shm/ + /var/lib/vmware/osdata/):' >> triage_results.txt
echo 'filename,size,user,group,type,perms,inode,hardlinks,access,modification,change' >> triage_results.txt
# Some directories will be visited twice, but we want to collect as much info as possible in the most portable way...
find / /tmp/ /var/tmp/ /var/run/ /dev/shm/ /var/lib/vmware/osdata/ -xdev -exec stat -c '%N,%s,%u,%g,%F,%A,%i,%h,%x,%y,%z' {} \; >> triage_results.txt
echo '===== END OF TIMELINE' >> triage_results.txt
echo '===== VIB LIST:' >> triage_results.txt
esxcli software vib list >> triage_results.txt
echo '===== VIB LIST #2:' >> triage_results.txt
esxcli software vib get >> triage_results.txt
echo '===== ACCEPTANCE:' >> triage_results.txt
esxcli software acceptance get >> triage_results.txt
echo '===== SSH KEYS:' >> triage_results.txt
esxcli system ssh key list >> triage_results.txt
echo '===== BMC:' >> triage_results.txt
localcli hardware ipmi bmc get  >> triage_results.txt
echo '===== CORE DUMPS:' >> triage_results.txt
ls -lht /var/core/ >> triage_results.txt
echo '===== UNUSUAL EXECUTABLES IN /VAR:' >> triage_results.txt
# This is an ugly hack to scan for ELF executables...
find /var/empty/ /var/lock/ /var/opt/ /var/run/ -type f -maxdepth 1 -exec grep -FHnom1 $'\x7FELF' {} \; | grep -F $':1:\x7FELF' | sed -e $'s/:1:\x7FELF$//g' > triage_elfs.txt
cat triage_elfs.txt >> triage_results.txt

# Copy at most two suspicious ELF binaries...
if [ -s triage_elfs.txt ]; then
	cat triage_elfs.txt | head -n 2 > triage_elfs_limit.txt
	mkdir triage_binaries

	copied=''
	while read -r; do
		copied='yes'
		cp "$REPLY" triage_binaries/
	done <triage_elfs_limit.txt

	if [ -z "$copied" ]; then # Fall back to something more portable and error-prone...
		while read -r elf; do
			cp "$elf" triage_binaries/
		done <triage_elfs_limit.txt
	fi
fi
rm -f triage_elfs.txt triage_elfs_limit.txt

# These core dumps can be encrypted (which isn't supported here), but many real-world configurations leave them unencrypted.
# We search for suspicious core dumps only (from 'vmx' and 'hostd' which deal with VM-controlled data, and also from 'sshd', if any)...
latest_core=$(ls -t /var/core/ | grep -E 'vmx|hostd|sshd' | head -n 1)
if [ -n "$latest_core" ]; then # If there is a core dump, check its encryption status.
	latest_core_enc=$(vmkdump_extract -E /var/core/"$latest_core")
	latest_core_bin=$(vmkdump_extract -e /var/core/"$latest_core" | head -n 1) # Also, extract the binary itself.
	[ "$latest_core_enc" = 'NO' ] || latest_core='' # It is encrypted, bail out.
	[ -f "$latest_core_bin" ] || latest_core_bin='' # No such a file, skip it.

	if [ -n "$latest_core" ]; then
		mkdir triage_cores
		cd triage_cores
		if [ $? -eq 0 ]; then
			vmkdump_extract -x /var/core/"$latest_core"
			cd ..
		fi
	fi
fi

if [ -n "$latest_core" ]; then
	echo 'Found a suspicious core dump...'
	echo " /var/core/$latest_core"
	[ -n "$latest_core_bin" ] && echo " crashed binary: $latest_core_bin"
	echo ' (Going to collect those...)'
fi

echo 'Compressing text results...'
gzip triage_results.txt
echo 'Collecting interesting files...'
if [ -n "$latest_core" ]; then
	if [ -n "$latest_core_bin" ]; then
		tar -cvhzf triage_files.tgz /var/log/ /log/ /scratch/log/ /tmp/ /var/tmp/ /dev/shm/ triage_binaries/ triage_cores/ "$latest_core_bin"
	else
		tar -cvhzf triage_files.tgz /var/log/ /log/ /scratch/log/ /tmp/ /var/tmp/ /dev/shm/ triage_binaries/ triage_cores/
	fi
else
	tar -cvhzf triage_files.tgz /var/log/ /log/ /scratch/log/ /tmp/ /var/tmp/ /dev/shm/ triage_binaries/
fi
[ -d triage_cores ] && rm -fr triage_cores/
[ -d triage_binaries ] && rm -fr triage_binaries/

echo 'Done!'
echo 'triage_results.txt.gz'
echo 'triage_files.tgz'
