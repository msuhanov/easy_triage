#!/bin/sh

# By Maxim Suhanov, CICADA8
# License: GPLv3 (see 'License.txt')

TOOL_VERSION='20250930-beta7'

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
find / /tmp/ /var/tmp/ /dev/shm/ /var/lib/vmware/osdata/ -xdev -exec stat -c '%N,%s,%u,%g,%F,%A,%i,%h,%x,%y,%z' {} \; >> triage_results.txt
echo '===== END OF TIMELINE' >> triage_results.txt
echo 'Compressing text results...'
gzip triage_results.txt
echo 'Collecting interesting files...'
tar -cvhzf triage_files.tgz /var/log/ /log/ /scratch/log/ /tmp/ /var/tmp/ /dev/shm/
echo 'Done!'
echo 'triage_results.txt.gz'
echo 'triage_files.tgz'
