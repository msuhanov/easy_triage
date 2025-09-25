#!/bin/sh

# By Maxim Suhanov, CICADA8
# License: GPLv3 (see 'License.txt')

TOOL_VERSION='20250925'

# We expect the hostname to be "sane":
HOSTNAME=$(hostname)

# The following six variables can be tuned...
OUT_DIR='artifact_collection_'"$HOSTNAME"
OUT_FILE='artifact_collection_'"$HOSTNAME"'.bin'

# Dump at most this number of orphan executables (executables deleted while running).
ORPHAN_LIMIT=4

# Collect NetScaler logs (/var/nslog/)? (Logs in /var/log/ aren't affected by this option.)
NS_LOGS='n'

# Collect NetScaler core dumps (/var/core/)? (Core dumps from other programs can be present there too.)
NS_CORE='y'

# Run the 'freebsd-update IDS' check (of the base system).
# This requires some free space and Internet connection (and it doesn't work on NetScaler appliances)!
UPDATE_IDS='n'

# Search for possible web shells (PHP) using this regex (grep -Ei):
WEBSHELL_REGEX='eval\($_|base64_decode\(|http_status_code\(|http_response_code\(40|array_filter\(|openssl_decrypt\(|str_rot13\(|hex2bin\(substr\(|base64_decode\($_|@array_filter'

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
sysctl netscaler >> "$OUT_DIR"/sysctl_netscaler.txt
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
ls -la / > "$OUT_DIR"/ls_root.txt
ls -la /dev/ >> "$OUT_DIR"/ls_dev.txt
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
[ -e /flash/boot/loader.conf ] && cat /flash/boot/loader.conf >> "$OUT_DIR"/flash_boot_loader_conf.txt
[ -e /netscaler/.signedexe.manifest ] && cat /netscaler/.signedexe.manifest | gzip >> "$OUT_DIR"/netscaler_signedexe_manifest.bin.gz
[ -e /var/python/.signedexe.manifest ] && cat /var/python/.signedexe.manifest | gzip >> "$OUT_DIR"/python_signedexe_manifest.bin.gz
[ -e /var/perl5/.signedexe.manifest ] && cat /var/perl5/.signedexe.manifest | gzip >> "$OUT_DIR"/perl_signedexe_manifest.bin.gz
which showtechsupport.pl >/dev/null 2>/dev/null && cat `which showtechsupport.pl` | gzip >> "$OUT_DIR"/showtechsupport.txt.gz
cat /root/mbox | gzip >> "$OUT_DIR"/root_mbox.txt.gz
cat /var/mail/root | gzip >> "$OUT_DIR"/var_mail_root.txt.gz
echo 'Done!'

echo 'Collecting possible persistence info...'
cat /etc/rc.local >> "$OUT_DIR"/etc_rc_local.txt
cat /etc/rc >> "$OUT_DIR"/etc_rc.txt
cat /etc/rc.conf >> "$OUT_DIR"/etc_rc_conf.txt
ls -la /etc/rc*.d/ >> "$OUT_DIR"/ls_etc_rc_all_d.txt
ls -la /etc/cron.d/ >> "$OUT_DIR"/ls_etc_cron_d.txt
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

tar -cvhzf "$OUT_DIR"/crond.tgz /etc/cron.d/

[ -e /etc/httpd.conf ] && cat /etc/httpd.conf >> "$OUT_DIR"/etc_httpd_conf.txt
[ -e /flash/nsconfig/rc.netscaler ] && cat /flash/nsconfig/rc.netscaler >> "$OUT_DIR"/flash_nsconfig_rc_netscaler.txt
[ -d /flash/nsconfig/ssh ] && ls -la /flash/nsconfig/ssh >> "$OUT_DIR"/flash_nsconfig_ssh.txt

# Passwords extracted here are encrypted.
[ -d /nsconfig ] && grep -H 'add system user ' /nsconfig/ns.conf /nsconfig/unified.conf >> "$OUT_DIR"/nsconfig_system_users.txt 2>/dev/null

# Usually, /nsconfig is a symlink to /flash/nsconfig, but who knows...
[ -d /nsconfig/ssh ] && ls -la /nsconfig/ssh >> "$OUT_DIR"/nsconfig_ssh.txt

# Collect the NetScaler web portal hashes, and validate them using the vendor's script...
[ -x /netscaler/portal_core_checksum_check.pl ] && cat /var/netscaler/logon/LogonPoint/checksum_*.txt >> "$OUT_DIR"/portal_core_checksum_check_hashes_all_vers.txt
[ -x /netscaler/portal_core_checksum_check.pl ] && /netscaler/portal_core_checksum_check.pl >> "$OUT_DIR"/portal_core_checksum_check_results.txt 2>> "$OUT_DIR"/portal_core_checksum_check_results.txt

# The 'check' argument is undocumented!
# Always run this tool before copying any executables! Otherwise, these copies will be detected and reported.
[ -x /netscaler/sigchk ] && /netscaler/sigchk check >> "$OUT_DIR"/sigchk_check.txt 2>/dev/null
echo 'Done!'

# Do this before collecting the timeline!
# NetScaler appliances log all unsigned scripts, filling the log files...
echo 'Archiving log files...'
if [ "$NS_LOGS" = 'y' ]; then
  tar -cvhzf "$OUT_DIR"/logs.tgz /var/log/ /var/nslog/
else
  tar -cvhzf "$OUT_DIR"/logs.tgz /var/log/
fi
echo 'Done!'

# On NetScaler appliances, collect binaries that trigger veriexec warnings.
if [ -d /var/nslog ]; then
  echo 'Collecting binaries that failed MAC check...'
  mkdir "$OUT_DIR"/binaries_failed

  # Let's examine kernel messages: in the current log file and in some of the previous ones...
  # (Skip entries that refer to this collector!)
  for fn_log in /var/log/messages /var/log/messages.0 /var/log/messages.1 /var/log/messages.2 /var/log/messages.3 /var/log/messages.4 /var/log/messages.5; do
    [ -e $fn_log ] || continue
    cat $fn_log | grep -Fa 'MAC/veriexec: no fingerprint (file=' | grep -Fva 'easy_triage' | grep -Fva '/stat.py' >> "$OUT_DIR"/binaries_failed_logs.txt
    cat $fn_log | grep -Fa 'MAC/veriexec: fingerprint does not match loaded value (file=' | grep -Fva 'easy_triage' | grep -Fva '/stat.py' >> "$OUT_DIR"/binaries_failed_logs.txt
  done

  # Also, handle compressed (gzip) log files...
  for fn_log in /var/log/messages.0.gz /var/log/messages.1.gz /var/log/messages.2.gz /var/log/messages.3.gz /var/log/messages.4.gz /var/log/messages.5.gz; do
    [ -e $fn_log ] || continue
    zcat $fn_log | grep -Fa 'MAC/veriexec: no fingerprint (file=' | grep -Fva 'easy_triage' | grep -Fva '/stat.py' >> "$OUT_DIR"/binaries_failed_logs.txt
    zcat $fn_log | grep -Fa 'MAC/veriexec: fingerprint does not match loaded value (file=' | grep -Fva 'easy_triage' | grep -Fva '/stat.py' >> "$OUT_DIR"/binaries_failed_logs.txt
  done

  # The path can be absolute or relative, it may contain spaces and backslashes (not escaped), so treat paths literally...
  #
  # There is a bug:
  # - When veriexec writes to the log aggressively, it can concatenate two log messages together. We ignore such lines.
  # - Example: "ppid=16308 gppid=9202)MAC/veriexec: no fingerprint".
  cat "$OUT_DIR"/binaries_failed_logs.txt | grep -Fva ')MAC/veriexec:' | grep -Eoa 'file=.* fsid=' | cut -d '=' -f 2- | sed -e 's/ fsid=//g' | sort | uniq >> "$OUT_DIR"/binaries_failed.txt_

  # Add the 'sigchk check' results...
  cat "$OUT_DIR"/sigchk_check.txt | grep -E '^/'  >> "$OUT_DIR"/binaries_failed.txt_ 2>/dev/null
  cat "$OUT_DIR"/binaries_failed.txt_ | sort | uniq > "$OUT_DIR"/binaries_failed.txt
  rm -f "$OUT_DIR"/binaries_failed.txt_

  cat "$OUT_DIR"/binaries_failed.txt | head -n 25 > "$OUT_DIR"/binaries_failed_logs_limit.txt
  while read -r fn; do
    [ -f "$fn" ] || continue
    echo " copying: $fn"
    cp -n "$fn" "$OUT_DIR"/binaries_failed/
    md5 "$fn" >>"$OUT_DIR"/files_copied.md5
  done <"$OUT_DIR"/binaries_failed_logs_limit.txt

  # Now, handle relative paths (assuming they are relative to /root/)...
  while read -r fn; do
    [ -f "$fn" ] && continue # Already copied it...
    [ -f /root/"$fn" ] || continue
    echo " copying: /root/$fn"
    cp -n /root/"$fn" "$OUT_DIR"/binaries_failed/
    md5 /root/"$fn" >>"$OUT_DIR"/files_copied.md5
  done <"$OUT_DIR"/binaries_failed_logs_limit.txt

  rm -f "$OUT_DIR"/binaries_failed_logs_limit.txt
  rm -f "$OUT_DIR"/binaries_failed_logs.txt
  echo 'Done!'
fi

[ -d /var/nslog ] && echo '' && echo '(On NetScaler appliances, timeline collection could take up to 4 hours!)' && echo ''
echo -n 'Collecting timeline... /'
echo 'filename,size,user,group,type_and_perms,inode,hardlinks,access,modification,change,birth' > "$OUT_DIR"/timeline.csv

# Unfortunately, there is no easy and portable way to use human-readable timestamps...
# Also, there could be no 'stat' command on NetScaler appliances...

stat=$(which stat 2>/dev/null)
[ -z "$stat" ] && stat="$OUT_DIR"/stat.py

# A hack for NetScaler appliances:
echo '#!/usr/bin/env python3' > "$OUT_DIR"/stat.py
echo 'import sys' >> "$OUT_DIR"/stat.py
echo 'import os' >> "$OUT_DIR"/stat.py
echo 'st = os.lstat(sys.argv[3])' >> "$OUT_DIR"/stat.py
echo 'print(",".join([sys.argv[3], str(st.st_size), str(st.st_uid), str(st.st_gid), str(st.st_mode), str(st.st_ino), str(st.st_nlink), str(st.st_atime), str(st.st_mtime), str(st.st_ctime), str(st.st_birthtime)]))' >> "$OUT_DIR"/stat.py
chmod +x "$OUT_DIR"/stat.py

find / -xdev -exec "$stat" -f '%N,%z,%u,%g,%p,%i,%l,%9Fa,%9Fm,%9Fc,%9FB' {} \; >> "$OUT_DIR"/timeline.csv 2>/dev/null
for dir in /usr /usr/local /tmp /var /var/tmp /var/log /var/nslog /nsconfig /var/audit /var/mail /var/crash /var/core* /var/netscaler /netscaler /var/vpn /var/nstrace /var/tmp/support /var/install /var/cron /var/www /home /home/* /root /nsroot /flash /srv; do
  mount | grep -F " on $dir (" 2>/dev/null >/dev/null
  [ $? -ne 0 ] && continue
  echo -n " $dir"
  find "$dir" -xdev -exec "$stat" -f '%N,%z,%u,%g,%p,%i,%l,%9Fa,%9Fm,%9Fc,%9FB' {} \; >> "$OUT_DIR"/timeline.csv 2>/dev/null
done
echo ' done!'

gzip "$OUT_DIR"/timeline.csv

echo 'Searching for SUID/SGID binaries...'
find /usr/bin/ /usr/sbin/ /bin/ /sbin/ /usr/local/ /libexec/ /tmp/ /var/tmp/ -maxdepth 4 -type f -a \( -perm -u+s -o -perm -g+s \) >> "$OUT_DIR"/file_suid_sgid.txt
echo 'Done!'

echo 'Collecting nscli history...'
cat /.nscli_history >> "$OUT_DIR"/nscli_rootdir_hist.txt
cat /var/nstmp/nsroot/.nscli_history >> "$OUT_DIR"/nscli_nsroot_hist.txt
cat '/var/nstmp/#nsinternal#'/.nscli_history >> "$OUT_DIR"/nscli_nsinternal_hist.txt

for fn in /var/nstmp/history.txt.*; do
  [ "$fn" = '/var/nstmp/history.txt.*' ] && continue
  echo "======= tail -n 50 $fn:" >> "$OUT_DIR"/spsh_hist_last50.txt
  tail -n 50 "$fn" >> "$OUT_DIR"/spsh_hist_last50.txt
  echo "======= end" >> "$OUT_DIR"/spsh_hist_last50.txt
done
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
  # This can be a symlink to /var/crash/core/...
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
# - Users are encouraged to [manually] spy on these processes using 'truss' (which seems to be blocked at the kernel level),
#     or dump the RAM.
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
  [ $? -eq 0 ] && pkg check -a -s 2>"$OUT_DIR"/pkg-check-a-s.txt # The 'pkg' command, when not bootstrapped, can block the execution!
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

# This command must be executed after the archive has been created!
# The -U argument is mostly undocumented, and if its current implementation changes, this command would block the execution (wait for user input).
# So, run it after anything else...

if [ -d /var/nslog ]; then
  sessions=$(nscli -U %%:.:. show system session 2>/dev/null)

  echo "$sessions" | grep -Fw '2)' 1>/dev/null 2>/dev/null
  if [ $? -eq  0 ]; then # More than one session found.
    OUT_BASE=$(basename "$OUT_FILE" .bin)
    OUT_FILE2="$OUT_BASE.txt"
    echo "$sessions" >> "$OUT_FILE2"
    echo "$OUT_FILE2"
  fi
fi

# For NetScaler appliances:
#
# - Some additional NSPPE-specific information can be dumped using these commands:
# nscli -U %%:nsroot:. show ip
# nscli -U %%:nsroot:. show interface
# nscli -U %%:nsroot:. show cluster instance
# nscli -U %%:nsroot:. show cluster node
#
# - And for HA/HA-INC setups (although this isn't NSPPE-specific):
# nscli -U %%:nsroot:. show ha node
#
# - Also, for all setups, RPC configuration (encrypted passwords and options):
# nscli -U %%:nsroot:. show rpc
#
# - These commands aren't executed here, because we don't care about such details.
