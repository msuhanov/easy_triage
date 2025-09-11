#!/bin/sh

# By Maxim Suhanov, CICADA8
# License: GPLv3 (see 'License.txt')

TOOL_VERSION='20250911-beta1'

# We expect the hostname to be "sane":
HOSTNAME=$(hostname)

# The following six variables can be tuned...
OUT_DIR='artifact_collection_'"$HOSTNAME"
OUT_FILE='artifact_collection_'"$HOSTNAME"'.bin'

# Dump at most this number of orphan executables (executables deleted while running).
ORPHAN_LIMIT=4

# Collect NetScaler logs (/var/nslog/)? (Logs in /var/log/ aren't affected by this option.)
NS_LOGS='y'

# Collect NetScaler core dumps (/var/core/)? (Core dumps from other programs can be present there too.)
NS_CORE='y'

# Run the 'freebsd-update IDS' check (of the base system).
# This requires some free space and Internet connection (and it doesn't work on NetScaler appliances)!
UPDATE_IDS='n'

# Search for possible web shells (PHP) using this regex (grep -Ei):
WEBSHELL_REGEX='eval\($_|base64_decode\(|http_status_code\(|http_response_code\(40|array_filter\(|openssl_decrypt\('

# Some sanity checks for user-supplied variables and hostname...
[ -n "$OUT_DIR" ] || exit 255
[ -n "$OUT_FILE" ] || exit 255
[ -n "$HOSTNAME" ] || exit 255

echo 'Running easy_triage_fbsd...'
echo "  version: $TOOL_VERSION"

if [ -d "$OUT_DIR" ]; then
  # Let the user decide whether to delete this directory or not...
  echo "Output directory already exists: $OUT_DIR"
  echo 'Refusing to run :-('
  exit 1
fi

mkdir "$OUT_DIR"
if [ $? -ne 0 ]; then # Something went wrong, refuse to run...
  echo 'Cannot create output directory, refusing to run :-('
  exit 1
fi

echo 'Collecting system & process & network info...'
date >> "$OUT_DIR"/date.txt
pwd >> "$OUT_DIR"/pwd.txt
uptime >> "$OUT_DIR"/uptime.txt
hostname >> "$OUT_DIR"/hostname.txt
whoami >> "$OUT_DIR"/whoami.txt
id >> "$OUT_DIR"/id.txt
uname -a >> "$OUT_DIR"/uname-a.txt
cat /etc/os-release >> "$OUT_DIR"/os-release.txt
ps -auxww -o ppid,ucomm,lstart >> "$OUT_DIR"/ps_custom.txt
ps aux >> "$OUT_DIR"/ps-aux.txt
ps auxww >> "$OUT_DIR"/ps-auxww.txt
procstat -a >> "$OUT_DIR"/procstat-a.txt
procstat -a -b >> "$OUT_DIR"/procstat-a-b.txt 2>> "$OUT_DIR"/procstat-a-b.txt
netstat -a -n >> "$OUT_DIR"/netstat-a-n.txt
netstat -r -n >> "$OUT_DIR"/netstat-r-n.txt
sockstat -n >> "$OUT_DIR"/sockstat-n.txt 2>/dev/null || sockstat >> "$OUT_DIR"/sockstat.txt
ifconfig -a >> "$OUT_DIR"/ifconfig-a.txt
cat /etc/resolv.conf >> "$OUT_DIR"/etc_resolv_conf.txt
cat /etc/hosts >> "$OUT_DIR"/etc_hosts.txt
arp -a >> "$OUT_DIR"/arp-a.txt
w -n >> "$OUT_DIR"/w-n.txt
dmesg -a >> "$OUT_DIR"/dmesg-a.txt
sysctl dev >> "$OUT_DIR"/sysctl_dev.txt
sysctl security >> "$OUT_DIR"/sysctl_security.txt
sysctl hw >> "$OUT_DIR"/sysctl_hw.txt
last -w -y >> "$OUT_DIR"/last-w-y.txt
lastlogin >> "$OUT_DIR"/lastlogin.txt
lastcomm >> "$OUT_DIR"/lastcomm.txt 2>/dev/null
fstat >> "$OUT_DIR"/fstat.txt 2>/dev/null
lsof -b >> "$OUT_DIR"/lsof-b.txt 2>/dev/null
geom -t >> "$OUT_DIR"/geom-t.txt 2>/dev/null
geom disk list >> "$OUT_DIR"/geom_disk_list.txt
mount >> "$OUT_DIR"/mount.txt
df -h >> "$OUT_DIR"/df-h.txt
cat /etc/passwd >> "$OUT_DIR"/passwd.txt
cat /etc/group >> "$OUT_DIR"/group.txt
cat /etc/rc.conf >> "$OUT_DIR"/etc_rc_conf.txt
cat /etc/pf.conf >> "$OUT_DIR"/etc_pf_conf.txt
cat /etc/ipfw.rules >> "$OUT_DIR"/etc_ipfw_rules.txt
cat /etc/ipf.rules >> "$OUT_DIR"/etc_ipf_rules.txt
cat /etc/ipf6.rules >> "$OUT_DIR"/etc_ipf6_rules.txt
pfctl -s rules >> "$OUT_DIR"/pfctl-s_rules.txt
pfctl -s nat >> "$OUT_DIR"/pfctl-s_nat.txt
pfctl -s states >> "$OUT_DIR"/pfctl-s_states.txt
ipfw list >> "$OUT_DIR"/ipfw_list.txt
echo 'Done!'

echo 'Collecting possible persistence info...'
cat /etc/rc.local >> "$OUT_DIR"/etc_rc_local.txt
cat /etc/crontab >> "$OUT_DIR"/etc_crontab.txt
atq >> "$OUT_DIR"/atq.txt
atq -v >> "$OUT_DIR"/atq-v.txt
crontab -u root -l >> "$OUT_DIR"/crontab_root.txt
crontab -u nsroot -l >> "$OUT_DIR"/crontab_nsroot.txt
crontab -u nobody -l >> "$OUT_DIR"/crontab_nobody.txt

last_user=$(cat /etc/passwd | cut -d ':' -f 1 | grep -Ev '^(nobody|root|nsroot)$' | tail -n 1)
if [ -n "$last_user" ]; then
	crontab -u "$last_user" -l >> "$OUT_DIR"/crontab_"$last_user".txt
fi
echo 'Done!'

echo 'Archiving log files...'
if [ "$NS_LOGS" = 'y' ]; then
  tar -cvhzf "$OUT_DIR"/logs.tgz /var/log/ /var/nslog/
else
  tar -cvhzf "$OUT_DIR"/logs.tgz /var/log/
fi
echo 'Done!'

[ -d /var/nslog ] && echo '' && echo '(On NetScaler appliances, timeline collection could take up to 4 hours!)' && echo ''
echo -n 'Collecting timeline... /'
echo 'filename,size,user,group,type_and_perms,inode,hardlinks,access,modification,change,birth' > "$OUT_DIR"/timeline.csv

# Unfortunately, there is no easy and portable way to use human-readable timestamps...
# Also, there could be no 'stat' command on NetScaler appliances...

stat=$(which stat 2>/dev/null)
[ -z "$stat" ] && stat="$OUT_DIR"/stat.py

echo '#!/usr/bin/env python3' > "$OUT_DIR"/stat.py
echo 'import sys' >> "$OUT_DIR"/stat.py
echo 'import os' >> "$OUT_DIR"/stat.py
echo 'st = os.lstat(sys.argv[3])' >> "$OUT_DIR"/stat.py
echo 'print(",".join([sys.argv[3], str(st.st_size), str(st.st_uid), str(st.st_gid), str(st.st_mode), str(st.st_ino), str(st.st_nlink), str(st.st_atime), str(st.st_mtime), str(st.st_ctime), str(st.st_birthtime)]))' >> "$OUT_DIR"/stat.py
chmod +x "$OUT_DIR"/stat.py

find / -xdev -exec "$stat" -f '%N,%z,%u,%g,%p,%i,%l,%9Fa,%9Fm,%9Fc,%9FB' {} \; >> "$OUT_DIR"/timeline.csv
for dir in /usr /usr/local /tmp /var /var/tmp /var/log /var/nslog /nsconfig /var/audit /var/mail /var/crash /var/core* /var/netscaler /netscaler /var/vpn /var/nstrace /var/tmp/support /var/install /var/cron /var/www /home /home/* /root /nsroot /flash /srv; do
  mount | grep -F " on $dir (" 2>/dev/null >/dev/null
  [ $? -ne 0 ] && continue
  echo -n " $dir"
  find "$dir" -xdev -exec "$stat" -f '%N,%z,%u,%g,%p,%i,%l,%9Fa,%9Fm,%9Fc,%9FB' {} \; >> "$OUT_DIR"/timeline.csv
done
echo ' done!'

gzip "$OUT_DIR"/timeline.csv

echo 'Searching for SUID/SGID binaries...'
find /usr/bin/ /usr/sbin/ /bin/ /sbin/ /usr/local/ /tmp/ /var/tmp/ -maxdepth 4 -type f -a \( -perm -u+s -o -perm -g+s \) >> "$OUT_DIR"/file_suid_sgid.txt
echo 'Done!'

echo 'Collecting artifacts from home directories...'

temp_file=$(mktemp)
[ -z "$temp_file" ] && temp_file='/tmp/tmp.xXHuL2Ilbz'

find -X /root/ /nsroot/ /home/*/ -mindepth 1 -maxdepth 1 | grep -E '/\.(sh_history|bash_history|python_history|history|lesshst|wget-hsts)$' >> "$temp_file"
while read -r fn; do
  echo "======= tail -n 50 $fn:" >> "$OUT_DIR"/hist_last50.txt
  tail -n 50 "$fn" >> "$OUT_DIR"/hist_last50.txt
  echo "======= end" >> "$OUT_DIR"/hist_last50.txt
done <"$temp_file"
rm -f "$temp_file"
echo 'Done!'

echo 'Collecting SSH artifacts and binaries...'
tar -cvhzf "$OUT_DIR"/ssh.tgz /root/.ssh/ /home/*/.ssh/ /nsconfig/ssh/ /nsconfig/sshd_config /etc/ssh/sshd_config /etc/sshd_config `which ssh` `which sshd`
echo 'Done!'

echo 'Archiving temp files...'
tar -cvhzf "$OUT_DIR"/temp.tgz /tmp/ /var/tmp/
echo 'Done!'

if [ "$NS_CORE" = 'y' ]; then
  echo 'Archiving core dumps (/var/core/ only)...'
  tar -cvhzf "$OUT_DIR"/core.tgz /var/core/
  echo 'Done!'
fi

echo 'Searching for orphan executables...'

procstat -a -b >/dev/null 2>"$temp_file"
orphan_pids=$(grep -Eo 'kern\.proc\.pathname: [[:digit:]]{1,}: ' "$temp_file" | cut -d ' ' -f 2 | cut -d ':' -f 1)
echo "$orphan_pids" | sort | uniq >> "$OUT_DIR"/orphan_pids.txt

# Dump at most $ORPHAN_LIMIT processes...
# Notes:
# - Unfortunately, this doesn't work on older versions of FreeBSD (the '-k' argument can be unsupported by 'gcore').
# - All current (as of 2025-09: versions 13.1 & 14.1) NetScaler firmware doesn't support 'gcore -k'... :-(
# - Users are encouraged to [manually] spy on these processes using 'truss', or dump the RAM.
orphan_pids_limit=$(head -n $ORPHAN_LIMIT "$OUT_DIR"/orphan_pids.txt)
for pid in $orphan_pids_limit; do
  echo "  dumping PID: $pid"
  echo "Processing PID: $pid" >> "$OUT_DIR"/orphan_dump.txt
  mkdir "$OUT_DIR"/binaries_orphan 2>/dev/null
  gcore -k -c "$OUT_DIR"/binaries_orphan/orphan_$pid.bin $pid >> "$OUT_DIR"/orphan_dump.txt 2>> "$OUT_DIR"/orphan_dump.txt
  gzip "$OUT_DIR"/binaries_orphan/orphan_$pid.bin 2>/dev/null
done

rm -f "$temp_file"
echo 'Done!'

echo 'Checking integrity of packages...'
freebsd_version_supported=$(uname -U | grep -E '^(10|11|12|13|14|15|16)' >/dev/null 2>/dev/null)
if [ -n "$freebsd_version_supported" ]; then # On very old versions of FreeBSD (<= 9), 'pkg -N' can wait for user input...
  pkg -N >> "$OUT_DIR"/pkg-bootstrapped.txt 2>> "$OUT_DIR"/pkg-bootstrapped.txt
  [ $? -eq 0 ] && pkg check -a -s 2>"$OUT_DIR"/pkg-check-a-s.txt # The 'pkg', when not bootstrapped, can block the execution!
fi

if [ "$UPDATE_IDS" = 'y' ]; then
  echo 'Checking integrity of base system...'
  freebsd-update IDS >> "$OUT_DIR"/freebsd-update-ids.txt 2>> "$OUT_DIR"/freebsd-update-ids.txt
  echo 'Done!'
fi

echo 'Searching for possible web shells...'
find /var/www/ /usr/local/www/ /srv/ /usr/local/apache/htdocs/ /var/vpn/ /var/netscaler/ -type f -name '*.php*' -exec grep -EiaH -B 15 -A 25 "$WEBSHELL_REGEX" {} \; >> "$OUT_DIR"/web_shells.txt
gzip "$OUT_DIR"/web_shells.txt
echo 'Done!'

echo 'Finalizing and packing results...'
echo "$TOOL_VERSION" > "$OUT_DIR"/easy_triage_version.txt
rm -f "$OUT_FILE"
tar -cvhzf "$OUT_FILE" "$OUT_DIR" >/dev/null 2>/dev/null
[ -r "$OUT_DIR/date.txt" ] && [ -r "$OUT_DIR/easy_triage_version.txt" ] && rm -fr "$OUT_DIR"
echo 'Done!'

echo 'All done!'
echo "$OUT_FILE"
