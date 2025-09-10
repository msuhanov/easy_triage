#!/bin/bash

# By Maxim Suhanov, CICADA8
# License: GPLv3 (see 'License.txt')

TOOL_VERSION='20250910'

if [ -z "$EUID" ]; then # Anything other than Bash is not supported!
  echo 'Not running under Bash :-('
  exit 1
fi

# Build a "sane" hostname string:
which strings 1>/dev/null 2>/dev/null
if [ $? -eq 0 ]; then
  HOSTNAME_SANE=$(hostname | strings -n 1 | head -n 1 | sed -e 's/ /_/g' -e 's/\//_/g' -e 's/\\/_/g')
else # On some systems, there is no 'strings'...
  HOSTNAME_SANE=$(hostname | head -n 1 | sed -e 's/ /_/g' -e 's/\//_/g' -e 's/\\/_/g')
fi

# The following four variables can be tuned...
OUT_DIR='artifact_collection_'"$HOSTNAME_SANE"
OUT_FILE='artifact_collection_'"$HOSTNAME_SANE"'.bin'

# Triage options, any combination of:
# - 'swap' (carve interesting strings from swap, currently this is limited to the "Accepted (password|...) from" strings);
# - 'orphan' (dump deleted but running executables, both from the disk and from the memory);
# - 'internet' (check Internet connectivity, get external IP address through 'icanhazip.com', and get date & time from online server);
# - 'rootkit' (search for hidden PIDs by scanning the /proc directory, trying to locate PIDs hidden from the readdir()-like calls);
# - 'qemu' (find a suspicious "headless" QEMU VM, if any, and copy its virtual disk, writing at most 64 MiB of its data);
# - 'omproc' (find processes having their /proc/<pid>/ directories overmounted, which is utilized by some userspace rootkits);
# - 'strace' (trace basic network activity of suspicious processes, no more than 5 processes and no longer than 3-4 minutes; the 'strace' package will be installed if needed).
# (Their order does not matter.)
TRIAGE_OPTIONS='swap orphan internet rootkit qemu omproc strace'

# Refuse to run if there is not enough disk space:
FREESPACE_THRESHOLD=1048576 # In 1024-byte blocks.

# Regular expression (grep -Ei) to examine command history files:
HISTORY_REGEX='wget|curl|qemu|http|tcp|tor|tunnel|reverse|socks|proxy|cred|ssh|php|perl|python|\.py|\.sh|\.sql|tmp|temp|shm|splo|xplo|cve|gcc|chmod|passwd|shadow|useradd|authorized_keys|hosts|[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}|github|pastebin|cdn|(:| )(443|80|22|445|3389)|nmap|scan|dump|flood|ddos|ncat|netcat|gsock|gs.sock|gssock|g.sock|a\.out|HISTFILE|preload|sh_history|whoami|^w$|\.io'

# Syscall filters (strace -e):
STRACE_FILTER='connect,bind,listen,accept,getpeername'

# Common locations for PAM modules across distributions:
PAM_LOCATIONS=(
    "/lib/security/"
    "/lib64/security/"
    "/usr/lib/security/"
    "/usr/lib64/security/"
    "/lib/x86_64-linux-gnu/security/"
    "/lib/i386-linux-gnu/security/"
    "/usr/lib/x86_64-linux-gnu/security/"
    "/usr/local/lib/security/"
    "/usr/local/lib64/security/"
)

# Common locations of .so libraries:
LIB_LOCATIONS=(
    "/lib/"
    "/usr/lib/"
    "/lib64/"
    "/usr/lib64/"
    "/usr/local/lib/"
    "/usr/local/lib64/"
    "/lib/x86_64-linux-gnu/"
    "/usr/lib/x86_64-linux-gnu/"
)

resolve_lib() { # Resolve a given file name ('*.so') to an expected library path.
  if [ -n "$1" -a -f "$1" ]; then
    printf '%s\n' "$1"
    return
  fi

  printf '%s\n' "$1" | grep -F '/' >/dev/null 2>/dev/null
  if [ $? -eq 1 ]; then
    fn=$(printf '%s\n' "$1" | sed -e 's/ //g') # Sometimes there is an extra space character, deal with it!
    if [ -n "$fn" ]; then
      for location in "${LIB_LOCATIONS[@]}"; do
        if [ -f "$location/$fn" ]; then
          printf '%s\n' "$location/$fn"
          return
        fi
      done
    fi
  else
    fn=$(printf '%s\n' "$1" | sed -e 's/ //g') # Remove spaces...
    [ -n "$fn" -a -f "$fn" ] && printf '%s\n' "$fn"
  fi
}

# Some sanity checks for user-supplied variables and sanitized hostname...
[ -n "$OUT_DIR" ] || exit 255
[ -n "$OUT_FILE" ] || exit 255
[ -n "$FREESPACE_THRESHOLD" -a $FREESPACE_THRESHOLD -gt 1024 ] || exit 255
[ -n "$HOSTNAME_SANE" ] || exit 255

echo 'easy_triage (for GNU/Linux) by CICADA8'
echo " version: $TOOL_VERSION"
echo " euid: $EUID (empty if not Bash)"
echo " hostname: $HOSTNAME_SANE"
pwd=$(pwd)
echo " pwd: $pwd"
echo ''

free_blocks=$(df -k -P . | tail -n 1 | awk '{ print $4 }' 2>/dev/null)
if [ -n "$free_blocks" ]; then
  echo ' available 1k-blocks of disk space: '"$free_blocks"
  echo ''

  if [ $free_blocks -lt $FREESPACE_THRESHOLD ]; then
    echo 'Not enough disk space, refusing to run :-('
    exit 1
  fi
fi

if [ -r "$OUT_DIR/check_file.sh" -o -r "$OUT_DIR/w.txt" -o -r "$OUT_DIR/ss-anp.txt" ]; then
  echo 'Output directory already exists...'

  # If restarting the script, preserve the old timeline file...
  echo 'Preserving old timeline...'
  temp_file=$(mktemp -u)
  [ -z "$temp_file" ] && temp_file='/tmp/tmp.xXHuL2Ilbz'

  gunzip "$OUT_DIR/timeline.csv.gz" 2>/dev/null
  mv "$OUT_DIR/timeline.csv" "$temp_file" || temp_file=''

  echo 'Done! Now, remove output directory...'
  rm -fr "$OUT_DIR" # Dangerous.
  echo 'Done!'
  echo ''
else
  temp_file=''
fi

mkdir "$OUT_DIR"
if [ $? -ne 0 ]; then # Something went wrong, refuse to run...
  echo 'Cannot create output directory, refusing to run :-('
  exit 1
fi

[ -n "$temp_file" -a -r "$temp_file" ] && cat "$temp_file" | gzip -4 1>"$OUT_DIR/timeline_old.csv.gz"
[ -n "$temp_file" -a -r "$temp_file" ] && rm -f "$temp_file" && echo 'Saved the old timeline!'

echo '(You can ignore any "command not found" message below.)'
echo ''

echo 'Collecting network info...'
ss -anp 1>"$OUT_DIR/ss-anp.txt"
netstat -anp 1>"$OUT_DIR/netstat-anp.txt"
ss -an 1>"$OUT_DIR/ss-an.txt"
netstat -an 1>"$OUT_DIR/netstat-an.txt"
ip addr 1>"$OUT_DIR/ip-addr.txt"
ip route 1>"$OUT_DIR/ip-route.txt"
ip neighbor 1>"$OUT_DIR/ip-neighbor.txt"
arp -a 1>"$OUT_DIR/arp-a.txt"
ifconfig -a 1>"$OUT_DIR/ifconfig-a.txt"
iwconfig 2>/dev/null 1>"$OUT_DIR/iwconfig.txt"
iwgetid 1>"$OUT_DIR/iwgetid.txt"
nmcli -t 1>"$OUT_DIR/nmcli-t.txt"
iptables -L -v -n 1>"$OUT_DIR/iptables-Lvn.txt"
cat /etc/hosts.allow 1>"$OUT_DIR/hosts_allow.txt"
resolvectl show-cache 2>/dev/null 1>"$OUT_DIR/resolvectl-show-cache.txt"

if [ ! -s "$OUT_DIR/resolvectl-show-cache.txt" ]; then
  # Force the systemd-resolved to dump its cache data into the journal.
  pkill -USR1 systemd-resolve # Not a typo (correct: "systemd-resolved"), there is a 15-characters limit for process name patterns...
fi

resolvectl status 2>/dev/null 1>"$OUT_DIR/resolvectl-status.txt"
cat /etc/resolv.conf 1>"$OUT_DIR/etc_resolv_conf.txt"
cat /etc/hosts 1>"$OUT_DIR/etc_hosts.txt"
echo 'Done!'

echo 'Collecting process info...'
ps auxww 1>"$OUT_DIR/ps-auxww.txt"
ps aux 1>"$OUT_DIR/ps-aux.txt"
ps -deaf 1>"$OUT_DIR/ps-deaf.txt"
ps -efl 1>"$OUT_DIR/ps-efl.txt"
ps -e -o pid,ppid,comm,cmd -w -w 1>"$OUT_DIR/ps_custom.txt"
find /proc -maxdepth 2 -name 'exe' -exec ls -l --full-time {} \; 2>/dev/null 1>>"$OUT_DIR/proc_all_exe.txt"

which strings 1>/dev/null 2>/dev/null
if [ $? -eq 0 ]; then
  find /proc -maxdepth 2 -name 'cmdline' -exec strings -n 1 --print-file-name {} \; 2>/dev/null 1>>"$OUT_DIR/proc_all_cmdline_1.txt"
  find /proc -maxdepth 2 -name 'cmdline' -print -exec strings -n 1 {} \; 2>/dev/null 1>>"$OUT_DIR/proc_all_cmdline_2.txt" # For non-GNU 'strings'...
  find /proc -maxdepth 2 -name 'comm' -print -exec strings -n 1 {} \; 2>/dev/null 1>>"$OUT_DIR/proc_all_comm.txt"
fi
echo 'Done!'

echo 'Collecting other system info...'
uptime 1>"$OUT_DIR/uptime.txt"
w 1>"$OUT_DIR/w.txt"
w -fi 1>"$OUT_DIR/w-fi.txt"
who -a 1>"$OUT_DIR/who-a.txt"
cat /proc/cmdline 1>"$OUT_DIR/kernel_cmdline.txt"

date 1>"$OUT_DIR/date.txt"
cp /etc/timezone "$OUT_DIR/etc_timezone" 2>/dev/null
cp /etc/localtime "$OUT_DIR/etc_localtime"
printf '%s\n' "$pwd" 1>"$OUT_DIR/pwd.txt"

whoami 1>"$OUT_DIR/whoami.txt"
hostname 1>"$OUT_DIR/hostname.txt"
hostnamectl 1>"$OUT_DIR/hostnamectl.txt"
uname -a 1>"$OUT_DIR/uname-a.txt"
cat /etc/os-release 1>"$OUT_DIR/os-release.txt"
cat /etc/machine-id 1>"$OUT_DIR/machine-id.txt"

lsmod 1>"$OUT_DIR/kernel_modules_1.txt"
cat /proc/modules 1>"$OUT_DIR/kernel_modules_2.txt"
cat /sys/kernel/security/lockdown 1>"$OUT_DIR/kernel_lockdown_status.txt"
cat /sys/kernel/oops_count 1>"$OUT_DIR/kernel_oops_count.txt"
cat /sys/kernel/debug/tracing/tracing_on 1>"$OUT_DIR/kernel_tracing_status.txt"
cat /sys/kernel/debug/tracing/trace | tail -n 8000 | gzip -7 1>"$OUT_DIR/kernel_tracing_trace_first8000lines.txt.gz"

cat /proc/sys/kernel/tainted 1>"$OUT_DIR/kernel_tainted_code.txt"
tainted_code=$(cat "$OUT_DIR/kernel_tainted_code.txt")
if [ -n "$tainted_code" ]; then
  tainted_code_masked=$(echo $(($tainted_code & 13313)))
  if [ -n "$tainted_code_masked" -a $tainted_code_masked -eq 12288 ]; then
    echo " note: kernel tainted by out-of-tree and unsigned, but not proprietary module ($tainted_code)"
    echo 'An out-of-tree and unsigned, but not proprietary module is loaded' 1>"$OUT_DIR/kernel_tainted_code_human.txt"
  else
    echo 'Likely a benign situation' 1>"$OUT_DIR/kernel_tainted_code_human.txt"
  fi
fi

[ -r /sys/kernel/security/tpm0/binary_bios_measurements ] && cp /sys/kernel/security/tpm0/binary_bios_measurements "$OUT_DIR/tpm0_binary_bios_measurements"

if [ -d /sys/firmware/efi/efivars ]; then
  ls -l /sys/firmware/efi/efivars/ 1>"$OUT_DIR/ls_efivars.txt"

  # Dump EFI variables used by shim...
  for fn in /sys/firmware/efi/efivars/*-605dab50-e046-4300-abb6-3dd810dd8b23; do
    echo "$fn:" 1>>"$OUT_DIR/efivars_shim.txt"
    hexdump -C "$fn" 1>>"$OUT_DIR/efivars_shim.txt" || xxd "$fn" 1>>"$OUT_DIR/efivars_shim.txt"
    echo '---' 1>>"$OUT_DIR/efivars_shim.txt"
  done

  # Also, dump 'dbx'...
  hexdump -C /sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f 1>>"$OUT_DIR/efivars_dbx.txt" || xxd /sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f 1>>"$OUT_DIR/efivars_dbx.txt"

  # And 'db'...
  hexdump -C /sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f 1>>"$OUT_DIR/efivars_db.txt" || xxd /sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f 1>>"$OUT_DIR/efivars_db.txt"
fi

lastlog 1>"$OUT_DIR/lastlog.txt"
lastlog2 1>"$OUT_DIR/lastlog2.txt"

# On domain-joined systems, the 'lastlog' file can be really large (but sparse)...
mkdir "$OUT_DIR/lastlog/" && cp --sparse=always -t "$OUT_DIR/lastlog/" /var/log/lastlog*

last -Fi 1>"$OUT_DIR/last-Fi.txt"
lastb -Fi 1>"$OUT_DIR/lastb-Fi.txt"

lslogins 1>"$OUT_DIR/lslogins.txt"
lslogins -f 1>"$OUT_DIR/lslogins-f.txt" 2>/dev/null
lslogins -L 1>"$OUT_DIR/lslogins-L.txt" 2>/dev/null
lslogins -a 1>"$OUT_DIR/lslogins-a.txt" 2>/dev/null
lslogins --output-all --notruncate --raw 1>"$OUT_DIR/lslogins-output-all.txt" 2>/dev/null

wtmpdb last 1>"$OUT_DIR/wtmpdb_last.txt"
wtmpdb last -Fi 1>"$OUT_DIR/wtmpdb_last-Fi.txt"

cat /proc/mounts 1>"$OUT_DIR/mounts.txt"
mount 1>"$OUT_DIR/mount.txt"
swapon -s 1>"$OUT_DIR/swapon-s.txt"
lsblk 1>"$OUT_DIR/lsblk.txt"
lsblk -o name,fstype,size -n -r -p -b 1>"$OUT_DIR/lsblk_name_fstype_size.txt"
cat "$OUT_DIR/lsblk_name_fstype_size.txt" | grep -v '  ' | cut -d ' ' -f 1 | xargs -I '{}' file -s -L '{}' 1>>"$OUT_DIR/bdev_sigs.txt"
df -h 1>"$OUT_DIR/df-h.txt"

cat /etc/passwd 1>"$OUT_DIR/passwd.txt"
cat /etc/group 1>"$OUT_DIR/group.txt"
cat /etc/sudoers 1>"$OUT_DIR/sudoers.txt"
klist 1>"$OUT_DIR/kerberos.txt" 2>/dev/null

auditctl -l 1>"$OUT_DIR/audit_rules.txt" 2>/dev/null
auditctl -s 1>"$OUT_DIR/audit_status.txt" 2>/dev/null

lsusb -tv 1>"$OUT_DIR/lsusb-tv.txt" 2>/dev/null
[ -b /dev/sda ] && smartctl --all /dev/sda 1>"$OUT_DIR/smartctl-all-sda.txt" 2>/dev/null
[ -b /dev/sdb ] && smartctl --all /dev/sdb 1>"$OUT_DIR/smartctl-all-sdb.txt" 2>/dev/null
[ -b /dev/sdc ] && smartctl --all /dev/sdc 1>"$OUT_DIR/smartctl-all-sdc.txt" 2>/dev/null
[ -b /dev/sdd ] && smartctl --all /dev/sdd 1>"$OUT_DIR/smartctl-all-sdd.txt" 2>/dev/null
[ -b /dev/sda ] && hdparm -I /dev/sda 1>"$OUT_DIR/hdparm-i-sda.txt" 2>/dev/null
[ -b /dev/sdb ] && hdparm -I /dev/sdb 1>"$OUT_DIR/hdparm-i-sdb.txt" 2>/dev/null
[ -b /dev/sdc ] && hdparm -I /dev/sdc 1>"$OUT_DIR/hdparm-i-sdc.txt" 2>/dev/null
[ -b /dev/sdd ] && hdparm -I /dev/sdd 1>"$OUT_DIR/hdparm-i-sdd.txt" 2>/dev/null
lspci -vv 1>"$OUT_DIR/lspci-vv.txt" 2>/dev/null
lscpu 1>"$OUT_DIR/lscpu.txt" 2>/dev/null

# List files on '/media'-mounted NTFS volumes (root and '/Users' only)...
lsblk -o fstype,mountpoints -r -n | grep -E '^ntfs' | cut -d ' ' -f 2- | grep -E '^/media' 1>"$OUT_DIR/lsblk_ntfs.txt"
while read -r; do
  dir=$(echo -e "$REPLY")
  ls -lht --full-time "$dir" "$dir"/Users 2>/dev/null 1>"$OUT_DIR/ls_ntfs.txt"
done <"$OUT_DIR/lsblk_ntfs.txt"
rm -f "$OUT_DIR/lsblk_ntfs.txt"

systemd-ac-power -v 1>"$OUT_DIR/systemd-ac-power.txt" 2>/dev/null
systemd-detect-virt 1>"$OUT_DIR/systemd-detect-virt.txt" 2>/dev/null

cat /proc/kallsyms | gzip -4 1>"$OUT_DIR/kernel_kallsyms.txt.gz"

bpftool prog list 1>"$OUT_DIR/bpftool_prog_list.txt" 2>/dev/null
ls -l --full-time /sys/fs/bpf/ 1>"$OUT_DIR/sys_fs_bpf.txt" 2>/dev/null

which astra-interpreters-lock 1>/dev/null 2>/dev/null
if [ $? -eq 0 ]; then
  astra-interpreters-lock status 1>"$OUT_DIR/astra_interpreters_obscurity_status.txt" 2>/dev/null
  astra-interpreters-lock is-enabled 1>"$OUT_DIR/astra_interpreters_obscurity_enabled.txt" 2>/dev/null
  # There are more obscurity-related options, but these two are the most important ones for the "kiosk" mode...
  # If they are off, the "kiosk" mode is not working at all (and, in general, users can execute anything).
fi

mkdir "$OUT_DIR/proc_misc"
# Some malware is known to derive their body decryption keys from some of these files...
cat /proc/net/arp 1>"$OUT_DIR/proc_misc/net_arp.txt"
cat /proc/net/route 1>"$OUT_DIR/proc_misc/net_route.txt"
cat /proc/cpuinfo 1>"$OUT_DIR/proc_misc/cpuinfo.txt"
cat /proc/iomem 1>"$OUT_DIR/proc_misc/iomem.txt"
cat /proc/ioports 1>"$OUT_DIR/proc_misc/ioports.txt"
cat /proc/meminfo 1>"$OUT_DIR/proc_misc/meminfo.txt"
cat /proc/keys 1>"$OUT_DIR/proc_misc/keys.txt"
cat /proc/key-users 1>"$OUT_DIR/proc_misc/key-users.txt"
cat /proc/stat 1>"$OUT_DIR/proc_misc/stat.txt"
cat /proc/devices 1>"$OUT_DIR/proc_misc/devices.txt"
# '/proc/cmdline' is in '$OUT_DIR/kernel_cmdline.txt'!

# Also, obtain similar (hardware-related) data...
mkdir "$OUT_DIR/sys_dmi"
for i in $(echo /sys/devices/virtual/dmi/id/*); do
  [ -f $i ] || continue
  j=$(basename $i)
  cat $i 1>"$OUT_DIR/sys_dmi/$j.txt"
done

echo 'Done!'

# Logs (especially, audit logs) must be copied before creating the timeline (in case all commands are logged)...
echo 'Copying important logs...'
mkdir "$OUT_DIR/logs_audit/" && cp -n -R -t "$OUT_DIR/logs_audit/" /var/log/audit/
mkdir "$OUT_DIR/logs/" && cp -n -R -t "$OUT_DIR/logs/" /var/log/auth* /var/log/secure* /var/log/wtmp /var/log/wtmp2* /var/log/wtmp.* /var/log/wtmp-* /var/log/wtmp_* /var/log/btmp* /var/log/syslog* /var/log/kern* /var/log/messages* /var/log/firewall* /var/log/auditd.log* /var/log/audit.log* /var/log/boot.log* /var/log/dpkg.log* /var/log/yum.log* /var/log/dnf* /var/log/cron* /var/log/dmesg* /var/log/sudo.log*
mkdir "$OUT_DIR/logs_apt/" && cp -n -R -t "$OUT_DIR/logs_apt/" /var/log/apt/
mkdir "$OUT_DIR/logs_atop/" && cp -n -R -t "$OUT_DIR/logs_atop/" /var/log/atop/
mkdir "$OUT_DIR/logs_sudo/" && cp -n -R -t "$OUT_DIR/logs_sudo/" /var/log/sudo-io/
mkdir "$OUT_DIR/logs_wtmpdb/" && cp -n -R -t "$OUT_DIR/logs_wtmpdb/" /var/lib/wtmpdb/
mkdir "$OUT_DIR/logs_lastlog2/" && cp -n -R -t "$OUT_DIR/logs_lastlog2/" /var/lib/lastlog/
echo ' also, current dmesg -T'
dmesg -T -P 2>/dev/null 1>"$OUT_DIR/dmesg-T.txt" || dmesg -T 1>"$OUT_DIR/dmesg-T.txt"
echo ' also, journalctl -a -b all'
journalctl -a -b all -o short-iso-precise --no-pager | gzip -6 1>"$OUT_DIR/journalctl_all.txt.gz"

journal_cnt=$(journalctl -a -b all -o short-iso-precise --no-pager 2>/dev/null | head -n 4 | wc -l)
if [ $journal_cnt -ne 4 ]; then # Skip these, if '-b all' is supported on the machine.
  echo ' also, journalctl -a (for older systems)'
  journalctl -a --no-pager | gzip -4 1>"$OUT_DIR/journalctl_current_boot.txt.gz"
  echo ' also, journalctl -a -b -1 (for older systems)'
  journalctl -a -b -1 --no-pager | gzip -4 1>"$OUT_DIR/journalctl_minusone_boot.txt.gz"
  echo ' also, journalctl -a -b -2 (for older systems)'
  journalctl -a -b -2 --no-pager | gzip -4 1>"$OUT_DIR/journalctl_minustwo_boot.txt.gz"
  echo ' also, journalctl -a -b -3 (for older systems)'
  journalctl -a -b -3 --no-pager | gzip -4 1>"$OUT_DIR/journalctl_minusthree_boot.txt.gz"
fi

cp /var/run/utmp "$OUT_DIR/utmp"

which strings 1>/dev/null 2>/dev/null
if [ $? -eq 0 ]; then
  # Note: "data objects that shall be stored in the journal and are larger than the default threshold of 512 bytes are compressed before they are written to the file system".
  # (From 'man journald.conf'.)
  echo ' strings from /run/log/journal/, /run/journal/, and /var/log/journal/'
  find /run/log/journal/ /run/journal/ /var/log/journal/ -type f -exec strings -n 8 {} \; 2>/dev/null | gzip -4 1> "$OUT_DIR/journalctl_strings.txt.gz"
else
  echo ' and files from /run/log/journal/, /run/journal/, and /var/log/journal/'
  tar cvzf "$OUT_DIR/journalctl_files.tgz" /run/log/journal/ /run/journal/ /var/log/journal/
fi

mkdir "$OUT_DIR/var_spool_mail/" && cp -n -R -t "$OUT_DIR/var_spool_mail/" /var/spool/mail/ 2>/dev/null

which docker 1>/dev/null 2>/dev/null
if [ $? -eq 0 ]; then
  echo ' also, logs from Docker containers'
  docker container ps --all | grep -Eiv '^container' | cut -d ' ' -f 1 1> "$OUT_DIR/docker_containers.txt"
  mkdir "$OUT_DIR/logs_docker/"
  while read -r; do
    cn="$REPLY"
    [ -z "$cn" ] && continue
    echo "  $cn"
    docker container logs --timestamps "$cn" | gzip -8 1> "$OUT_DIR/logs_docker/$cn.txt.gz"
    docker container inspect "$cn" 1> "$OUT_DIR/logs_docker/$cn.insp"
  done <"$OUT_DIR/docker_containers.txt"
fi
echo 'Done!'

echo -n 'Collecting timeline... / '

echo 'inode,Hard Links,Path,Last Access,Last Modification,Last Status Change,Created,User,Group,Permissions,File Size (bytes)' 1>"$OUT_DIR/timeline.csv"
find / -xdev -print0 2>/dev/null | xargs -0 stat --printf='%i,%h,%n,%x,%y,%z,%w,%U,%G,%A,%s\n' 2>/dev/null 1>> "$OUT_DIR/timeline.csv"

for dir in /usr /tmp /var /var/tmp /var/log /var/run /var/lib /var/www /home /root /etc /opt /srv /www /data /boot /boot/efi /snap /run /lib /lib64; do
  findmnt --mountpoint "$dir" 1>/dev/null 2>/dev/null || continue
  echo -n "$dir "
  find "$dir" -xdev -print0 2>/dev/null | xargs -0 stat --printf='%i,%h,%n,%x,%y,%z,%w,%U,%G,%A,%s\n' 2>/dev/null 1>> "$OUT_DIR/timeline.csv"
done

if [ -d /dev/shm/ ]; then
  echo -n '/dev/shm/ '
  find /dev/shm/ -print0 2>/dev/null | xargs -0 stat --printf='%i,%h,%n,%x,%y,%z,%w,%U,%G,%A,%s\n' 2>/dev/null 1>> "$OUT_DIR/timeline.csv"
fi

# Scan through file descriptors and executables that are marked as deleted (but still present in the file system, because they are open).
# The timestamps are taken from symlink targets.
echo -n ' unlinked_but_open '
find /proc/ -mindepth 2 -maxdepth 3 \( ! -name 'fd' -prune \) \( -path '*/fd/*' -o -name 'exe' \) -type l -printf '%i,%n,%p -> %l,' -exec stat -L --printf '%x,%y,%z,%w,%U,%G,%A,%s\n' {} \; 2> /dev/null | grep -F '(deleted)' 1>> "$OUT_DIR/timeline.csv"

gzip -2 "$OUT_DIR/timeline.csv"
echo ' Done!'

# These files should be copied after creating the timeline (to preserve "old" last access timestamps)...
if [ -d /dev/shm/ ]; then
  echo 'Copying files from /dev/shm/...'
  mkdir "$OUT_DIR/dev_shm/" && cp -n -R -t "$OUT_DIR/dev_shm/" /dev/shm/ 2>/dev/null
  echo 'Done!'
fi

echo 'Copying recent crash/core dumps...'
mkdir "$OUT_DIR/crash_and_core/"
find /var/crash/ /var/lib/systemd/coredump/ -type f -mtime -61 -size -45M -print0 1>>"$OUT_DIR/recent_crash_dumps.txt"
cat "$OUT_DIR/recent_crash_dumps.txt" | xargs -0 -I '{}' cp --backup=numbered -t "$OUT_DIR/crash_and_core/" '{}'
cat "$OUT_DIR/recent_crash_dumps.txt" | xargs -0 -I '{}' md5sum '{}' 1>> "$OUT_DIR/files_copied.md5"
rm -f "$OUT_DIR/recent_crash_dumps.txt"
echo 'Done!'

echo 'Checking integrity of DEB/RPM packages...'
rpm -V -a 1>"$OUT_DIR/rpm-Va.txt" 2>/dev/null
dpkg -V 1>"$OUT_DIR/dpkg-V.txt" 2>/dev/null
debsums -a 1>"$OUT_DIR/debsums-a.txt" 2>/dev/null
echo 'Done!'

echo 'Collecting possible persistence info...'
atq 1>"$OUT_DIR/atq.txt" 2>/dev/null
crontab -l 1>"$OUT_DIR/crontab-l.txt" 2>/dev/null
cat /etc/rc.local 1>"$OUT_DIR/etc_rc_local.txt" 2>/dev/null
ls -la /etc/init.d/ /etc/rc*.d/ 1>"$OUT_DIR/etc_rc_scripts.txt" 2>/dev/null
cat /etc/ld.so.preload 1>"$OUT_DIR/etc_ld_so_preload.txt" 2>/dev/null
cat /proc/self/environ 1>"$OUT_DIR/environ.bin" 2>/dev/null
cat /etc/profile 1>"$OUT_DIR/etc_profile.txt" 2>/dev/null
cat /etc/bash.bashrc 1>"$OUT_DIR/etc_bash_bashrc.txt" 2>/dev/null
cat /root/.bashrc 1>"$OUT_DIR/root_bashrc.txt" 2>/dev/null
cat /root/mbox | gzip -9 1>"$OUT_DIR/root_mbox.txt.gz" 2>/dev/null
printf '%s\n' "$PATH" 1>"$OUT_DIR/path_variable.txt"

find /proc -mindepth 2 -maxdepth 2 -name 'environ' -type f -exec grep -Fl 'LD_PRELOAD=' {} \; 1>"$OUT_DIR/proc_all_ld_preload.txt" 2>/dev/null

# There are legitimate LD_PRELOAD use cases (like sandboxing), so limit the number of processes to examine...
cat "$OUT_DIR/proc_all_ld_preload.txt" | head -n 8 1>"$OUT_DIR/proc_all_ld_preload_limit.txt"
while read -r fn_env; do
  pid=$(echo "$fn_env" | cut -d '/' -f 3)
  cat "$fn_env" 1>"$OUT_DIR/environ.bin.$pid" 2>/dev/null
done <"$OUT_DIR/proc_all_ld_preload_limit.txt"
rm -f "$OUT_DIR/proc_all_ld_preload_limit.txt"

mkdir "$OUT_DIR/var_spool_cron/" && cp -n -R -t "$OUT_DIR/var_spool_cron/" /var/spool/cron/ 2>/dev/null
mkdir "$OUT_DIR/var_spool_anacron/" && cp -n -R -t "$OUT_DIR/var_spool_anacron/" /var/spool/anacron/ 2>/dev/null
mkdir "$OUT_DIR/etc_all_cron/" && cp -n -R -t "$OUT_DIR/etc_all_cron/" /etc/*cron* 2>/dev/null
mkdir "$OUT_DIR/etc_profile_d/" && cp -n -R -t "$OUT_DIR/etc_profile_d/" /etc/profile.d/ 2>/dev/null
mkdir "$OUT_DIR/systemd_lib_systemd_system/" && cp -n -R -t "$OUT_DIR/systemd_lib_systemd_system/" /lib/systemd/system/ 2>/dev/null
mkdir "$OUT_DIR/systemd_usr_lib_systemd_system/" && cp -n -R -t "$OUT_DIR/systemd_usr_lib_systemd_system/" /usr/lib/systemd/system/ 2>/dev/null
mkdir "$OUT_DIR/systemd_etc_systemd_system/" && cp -n -R -t "$OUT_DIR/systemd_etc_systemd_system/" /etc/systemd/system/ 2>/dev/null
mkdir "$OUT_DIR/systemd_lib_systemd_user/" && cp -n -R -t "$OUT_DIR/systemd_lib_systemd_user/" /lib/systemd/user/ 2>/dev/null
mkdir "$OUT_DIR/systemd_usr_lib_systemd_user/" && cp -n -R -t "$OUT_DIR/systemd_usr_lib_systemd_user/" /usr/lib/systemd/user/ 2>/dev/null
mkdir "$OUT_DIR/systemd_etc_systemd_user/" && cp -n -R -t "$OUT_DIR/systemd_etc_systemd_user/" /etc/systemd/user/ 2>/dev/null
mkdir "$OUT_DIR/xdg_etc_autostart/" && cp -n -R -t "$OUT_DIR/xdg_etc_autostart/" /etc/xdg/autostart/ 2>/dev/null

mkdir "$OUT_DIR/pamd_etc/" && cp -n -R -t "$OUT_DIR/pamd_etc/" /etc/pam.d/ 2>/dev/null

# Find all PAM modules and collect their hashes (timestamps were collected separately):
for location in "${PAM_LOCATIONS[@]}"; do
  if [ -d "$location" ]; then
    find "$location" -name "*.so" -type f -print0 2>/dev/null | xargs -I '{}' -0 md5sum '{}' 1>>"$OUT_DIR/pam_modules_hashes.txt"
  fi
done

# Hash EFI executables:
find /boot/efi/ -xdev -type f \( -iname '*.exe' -o -iname '*.efi' \) -exec md5sum {} \; 1>>"$OUT_DIR/efi_executables_hashes.txt"

echo 'Done!'

echo 'Copying binaries that failed hash check...'
mkdir "$OUT_DIR/binaries_failed"
cat "$OUT_DIR/rpm-Va.txt" "$OUT_DIR/dpkg-V.txt" | grep -E '^..5' | grep -Eo '/(usr|bin|sbin|lib|opt).+' | grep -Eiv '\.(conf|json|txt|htm|md)' 1>>"$OUT_DIR/failed_files_to_copy.txt"
while read -r; do
  fn="$REPLY"
  cp --backup=numbered -t "$OUT_DIR/binaries_failed/" "$fn"
  md5sum "$fn" 1>> "$OUT_DIR/files_copied.md5"
done <"$OUT_DIR/failed_files_to_copy.txt"
rm -f "$OUT_DIR/failed_files_to_copy.txt"
echo 'Done!'

echo 'Checking file signatures and copying suspicious files...'

# Helper script:
echo '#!/bin/bash' 1>"$OUT_DIR/check_file.sh"
echo '' 1>> "$OUT_DIR/check_file.sh"
echo '[ -n "$1" ] && [ -n "$2" ] || exit 1' 1>> "$OUT_DIR/check_file.sh"
echo '' 1>> "$OUT_DIR/check_file.sh"
echo 'signature=$(file -b "$1")' 1>> "$OUT_DIR/check_file.sh"
echo '' 1>> "$OUT_DIR/check_file.sh"
echo 'is_executable=$(echo "$signature" | grep -E "ELF|script|executable")' 1>> "$OUT_DIR/check_file.sh"
echo 'is_static_elf=$(echo "$signature" | grep -E "ELF.*static")' 1>> "$OUT_DIR/check_file.sh"
echo 'is_upx=$(dd if="$1" bs=304 count=1 2>/dev/null | grep -Fao "UPX")' 1>> "$OUT_DIR/check_file.sh"
echo 'is_github=$(grep -Fao "github.com/" "$1" 1>/dev/null)' 1>> "$OUT_DIR/check_file.sh"
echo 'is_suspicious_path=$(echo "$1" | grep -E "/tmp|/temp|/var/tmp/|/dev/shm/")' 1>> "$OUT_DIR/check_file.sh"
echo '' 1>> "$OUT_DIR/check_file.sh"
echo 'additional=""' 1>> "$OUT_DIR/check_file.sh"
echo '[ -n "$is_executable" -a -n "$is_suspicious_path" ] && additional="has suspicious path"' 1>> "$OUT_DIR/check_file.sh"
echo '[ -n "$is_executable" -a -n "$is_upx" ] && additional="likely UPX-packed"' 1>> "$OUT_DIR/check_file.sh"
echo '[ -n "$is_executable" -a -n "$is_github" ] && additional="contains link to GitHub"' 1>> "$OUT_DIR/check_file.sh"
echo 'echo "$1	$signature	$additional"' 1>> "$OUT_DIR/check_file.sh"
echo '' 1>> "$OUT_DIR/check_file.sh"
echo '[ -n "$is_static_elf" ] && cp --backup=numbered -t "$2" "$1" && md5sum "$1" && exit 0' 1>> "$OUT_DIR/check_file.sh"
echo '[ -n "$is_executable" -a -n "$is_github" ] && cp --backup=numbered -t "$2" "$1" && md5sum "$1" && exit 0' 1>> "$OUT_DIR/check_file.sh"
echo '[ -n "$is_executable" -a -n "$is_upx" ] && cp --backup=numbered -t "$2" "$1" && md5sum "$1" && exit 0' 1>> "$OUT_DIR/check_file.sh"
echo '[ -n "$is_executable" -a -n "$is_suspicious_path" ] && cp --backup=numbered -t "$2" "$1" && md5sum "$1" && exit 0' 1>> "$OUT_DIR/check_file.sh"
echo '' 1>> "$OUT_DIR/check_file.sh"
echo 'exit 1' 1>> "$OUT_DIR/check_file.sh"

chmod +x "$OUT_DIR/check_file.sh"

BIN_IS_SYMLINK=''
USR_SBIN_IS_SYMLINK=''
[ -h /bin ] && BIN_IS_SYMLINK='y'
[ -h /usr/sbin ] && USR_SBIN_IS_SYMLINK='y'
[ -n "$BIN_IS_SYMLINK" ] && echo 'Note: /bin is symlink'
[ -n "$USR_SBIN_IS_SYMLINK" ] && echo 'Note: /usr/sbin is symlink'

mkdir "$OUT_DIR/binaries_suspicious"

if [ -n "$BIN_IS_SYMLINK" ]; then
  if [ -n "$USR_SBIN_IS_SYMLINK" ]; then
    find /usr/bin/ /usr/local/ /tmp/ /var/tmp/ /dev/shm/ -maxdepth 4 -type f -exec "$OUT_DIR/check_file.sh" {} "$OUT_DIR"/binaries_suspicious/ \; 2>/dev/null 1>> "$OUT_DIR/file_sigs.txt"
  else
    find /usr/bin/ /usr/sbin/ /usr/local/ /tmp/ /var/tmp/ /dev/shm/ -maxdepth 4 -type f -exec "$OUT_DIR/check_file.sh" {} "$OUT_DIR"/binaries_suspicious/ \; 2>/dev/null 1>> "$OUT_DIR/file_sigs.txt"
  fi
  find /usr/lib*/ -maxdepth 2 -type f -exec "$OUT_DIR/check_file.sh" {} "$OUT_DIR"/binaries_suspicious/ \; 2>/dev/null 1>> "$OUT_DIR/file_sigs.txt"
  find /var/lib/cont* /var/lib/dock* /opt/lib/dock* /var/snap/docker -type f -exec "$OUT_DIR/check_file.sh" {} "$OUT_DIR"/binaries_suspicious/ \; 2>/dev/null 1>> "$OUT_DIR/file_sigs.txt"
else
  find /bin/ /sbin/ /usr/bin/ /usr/sbin/ /usr/local/ /tmp/ /var/tmp/ /dev/shm/ -maxdepth 4 -type f -exec "$OUT_DIR/check_file.sh" {} "$OUT_DIR"/binaries_suspicious/ \; 2>/dev/null 1>> "$OUT_DIR/file_sigs.txt"
  find /lib*/ /usr/lib*/ -maxdepth 2 -type f -exec "$OUT_DIR/check_file.sh" {} "$OUT_DIR"/binaries_suspicious/ \; 2>/dev/null 1>> "$OUT_DIR/file_sigs.txt"
  find /var/lib/cont* /var/lib/dock* /opt/lib/dock* /var/snap/docker -type f -exec "$OUT_DIR/check_file.sh" {} "$OUT_DIR"/binaries_suspicious/ \; 2>/dev/null 1>> "$OUT_DIR/file_sigs.txt"
fi

gzip -2 "$OUT_DIR/file_sigs.txt"
echo 'Done!'

echo 'Scanning for SUID/SGID files...'
if [ -n "$BIN_IS_SYMLINK" ]; then
  if [ -n "$USR_SBIN_IS_SYMLINK" ]; then
    find /usr/bin/ /usr/local/ /tmp/ /var/tmp/ /dev/shm/ -maxdepth 4 -type f -a \( -perm -u+s -o -perm -g+s \) 2>/dev/null 1>> "$OUT_DIR/file_suid_sgid.txt"
  else
    find /usr/bin/ /usr/sbin/ /usr/local/ /tmp/ /var/tmp/ /dev/shm/ -maxdepth 4 -type f -a \( -perm -u+s -o -perm -g+s \) 2>/dev/null 1>> "$OUT_DIR/file_suid_sgid.txt"
  fi
  find /usr/lib*/ -maxdepth 2 -type f -a \( -perm -u+s -o -perm -g+s \) 2>/dev/null 1>> "$OUT_DIR/file_suid_sgid.txt"
  find /var/lib/cont* /var/lib/dock* /opt/lib/dock* /var/snap/docker -type f -a \( -perm -u+s -o -perm -g+s \) 2>/dev/null 1>> "$OUT_DIR/file_suid_sgid.txt"
else
  find /bin/ /sbin/ /usr/bin/ /usr/sbin/ /usr/local/ /tmp/ /var/tmp/ /dev/shm/ -maxdepth 4 -type f -a \( -perm -u+s -o -perm -g+s \) 2>/dev/null 1>> "$OUT_DIR/file_suid_sgid.txt"
  find /lib*/ /usr/lib*/ -maxdepth 2 -type f -a \( -perm -u+s -o -perm -g+s \) 2>/dev/null 1>> "$OUT_DIR/file_suid_sgid.txt"
  find /var/lib/cont* /var/lib/dock* /opt/lib/dock* /var/snap/docker -type f -a \( -perm -u+s -o -perm -g+s \) 2>/dev/null 1>> "$OUT_DIR/file_suid_sgid.txt"
fi
echo 'Done!'

echo 'Copying SUID/SGID files...'
mkdir "$OUT_DIR/binaries_suid_sgid/"
while read -r; do
  fn="$REPLY"
  [ -z "$fn" ] && continue
  cp --backup=numbered -t "$OUT_DIR/binaries_suid_sgid/" "$fn"
  md5sum "$fn" 1>>"$OUT_DIR/files_copied.md5"
done <"$OUT_DIR/file_suid_sgid.txt"
echo 'Done!'

echo 'Copying preload libraries...'
mkdir "$OUT_DIR/binaries_preload/"

# Use the '/etc/ld.so.preload' file...
while read -r; do
  fn="$REPLY"
  [ -z "$fn" ] && continue
  echo " note: found $fn (ld.so.preload)"
  fn2=$(resolve_lib "$fn")
  [ -z "$fn2" ] && continue
  cp --backup=numbered -t "$OUT_DIR/binaries_preload/" "$fn2"
  md5sum "$fn2" 1>>"$OUT_DIR/files_copied.md5"
done <"$OUT_DIR/etc_ld_so_preload.txt"

# Use the environment variable...
cat "$OUT_DIR"/environ.bin* | tr '\0' '\n' | grep -E '^LD_PRELOAD=' | cut -d '=' -f 2- | tr ':' '\n' | tr ' ' '\n' | grep -Ev '^$' 1>"$OUT_DIR/environ_ld_preload.txt"
while read -r; do
  fn="$REPLY"
  [ -z "$fn" ] && continue
  echo " note: found $fn (environ)"
  fn2=$(resolve_lib "$fn")
  [ -z "$fn2" ] && continue
  cp --backup=numbered -t "$OUT_DIR/binaries_preload/" "$fn2"
  md5sum "$fn2" 1>>"$OUT_DIR/files_copied.md5"
done <"$OUT_DIR/environ_ld_preload.txt"
rm -f "$OUT_DIR/environ_ld_preload.txt"

# From systemd...
find "$OUT_DIR"/systemd_* -type f -name 'local.conf' -print0 | xargs -I '{}' -0 grep -Eo 'LD_PRELOAD( )*=( )*.+' '{}' | sed -e 's/"//g' -e "s/'//g" | cut -d '=' -f 2- | tr ':' '\n' 1>"$OUT_DIR/systemd_ld_preload.txt"
while read -r; do
  fn="$REPLY"
  [ -z "$fn" ] && continue
  echo " note: found $fn (systemd config)"
  fn2=$(resolve_lib "$fn")
  [ -z "$fn2" ] && continue
  cp --backup=numbered -t "$OUT_DIR/binaries_preload/" "$fn2"
  md5sum "$fn2" 1>>"$OUT_DIR/files_copied.md5"
done <"$OUT_DIR/systemd_ld_preload.txt"
rm -f "$OUT_DIR/systemd_ld_preload.txt"

echo 'Done!'

echo 'Copying segfaulting libraries (observed on last 2 boots)...'
mkdir "$OUT_DIR/binaries_segfault/"

# This boot.
grep -F 'segfault at ' "$OUT_DIR/dmesg-T.txt" | grep -Eo '[[:alnum:]]+\.so(\.[[:digit:]]{1,3}){0,1}' 1>"$OUT_DIR/segfault_libs.txt"

# Previous boot.
grep -F 'segfault at ' "$OUT_DIR/logs/dmesg.0" | grep -Eo '[[:alnum:]]+\.so(\.[[:digit:]]{1,3}){0,1}' 1>>"$OUT_DIR/segfault_libs.txt"

# Previous boot (the same one as above).
journalctl -b -1 | grep -F 'segfault at ' | grep -Eo '[[:alnum:]]+\.so(\.[[:digit:]]{1,3}){0,1}' 1>>"$OUT_DIR/segfault_libs.txt"

cat "$OUT_DIR/segfault_libs.txt" | grep -Ev '^libc\.so' | sort -T "$OUT_DIR" | uniq | head -n 6 1>>"$OUT_DIR/segfault_libs_.txt" # Limit the number of libraries, just in case...
mv "$OUT_DIR/segfault_libs_.txt" "$OUT_DIR/segfault_libs.txt"

while read -r; do
  fn="$REPLY"
  [ -z "$fn" ] && continue
  echo " note: found $fn"
  fn2=$(resolve_lib "$fn")
  [ -z "$fn2" ] && continue
  cp --backup=numbered -t "$OUT_DIR/binaries_segfault/" "$fn2"
  md5sum "$fn2" 1>>"$OUT_DIR/files_copied.md5"
done <"$OUT_DIR/segfault_libs.txt"
rm -f "$OUT_DIR/segfault_libs.txt"
echo 'Done!'

echo 'Collecting list of installed executables (DEB)...'
find /var/lib/dpkg/info -maxdepth 1 -type f -name '*.list' | xargs -I '{}' cat '{}' | grep -Ea '^/(usr/bin|usr/sbin|bin|sbin)/' | sort -T "$OUT_DIR" | uniq 1>> "$OUT_DIR/executables_deb.txt"
find /var/lib/dpkg/info -maxdepth 1 -type f -name '*.list' | xargs -I '{}' cat '{}' | grep -Ea '^(/usr|)/lib/systemd/' | sort -T "$OUT_DIR" | uniq 1>> "$OUT_DIR/executables_systemd_deb.txt"
echo 'Done!'

echo 'Collecting list of installed executables (RPM)...'
rpm -qal | grep -Ea '^/(usr/bin|usr/sbin|bin|sbin)/' | sort -T "$OUT_DIR" | uniq 1>> "$OUT_DIR/executables_rpm.txt"
rpm -qal | grep -Ea '^(/usr|)/lib/systemd/' | sort -T "$OUT_DIR" | uniq 1>> "$OUT_DIR/executables_systemd_rpm.txt"
echo 'Done!'

echo 'Searching for executables not from packages...'
cat "$OUT_DIR/executables_rpm.txt" "$OUT_DIR/executables_deb.txt" | sort -T "$OUT_DIR" | uniq > "$OUT_DIR/executables_from_packages_draft1.txt"

if [ -n "$BIN_IS_SYMLINK" ]; then
  # Still, some files are referenced through /bin/ and /sbin/, not through /usr/bin/ and /usr/sbin/... Fix this!
  cat "$OUT_DIR/executables_from_packages_draft1.txt" | sed -e 's/^\/usr\//\//g' > "$OUT_DIR/executables_from_packages_draft2.txt"
  cat "$OUT_DIR/executables_from_packages_draft1.txt" | sed -e 's/^\/bin\//\/usr\/bin\//g' -e 's/^\/sbin\//\/usr\/sbin\//g' > "$OUT_DIR/executables_from_packages_draft3.txt"

  if [ -n "$USR_SBIN_IS_SYMLINK" ]; then
    # Same, for the /usr/sbin!
    cat "$OUT_DIR/executables_from_packages_draft1.txt" | sed -e 's/^\/usr\/sbin/\/usr\/bin/g' > "$OUT_DIR/executables_from_packages_draft4.txt"
    cat "$OUT_DIR/executables_from_packages_draft1.txt" "$OUT_DIR/executables_from_packages_draft2.txt" "$OUT_DIR/executables_from_packages_draft3.txt" "$OUT_DIR/executables_from_packages_draft4.txt" | sort -T "$OUT_DIR" | uniq > "$OUT_DIR/executables_from_packages.txt"
    find /usr/bin/ -maxdepth 1 -type f | sort -T "$OUT_DIR" 2>/dev/null 1>> "$OUT_DIR/executables_present.txt"
  else
    cat "$OUT_DIR/executables_from_packages_draft1.txt" "$OUT_DIR/executables_from_packages_draft2.txt" "$OUT_DIR/executables_from_packages_draft3.txt" | sort -T "$OUT_DIR" | uniq > "$OUT_DIR/executables_from_packages.txt"
    find /usr/bin/ /usr/sbin/ -maxdepth 1 -type f | sort -T "$OUT_DIR" 2>/dev/null 1>> "$OUT_DIR/executables_present.txt"
  fi

  rm -f "$OUT_DIR/executables_from_packages_draft1.txt" "$OUT_DIR/executables_from_packages_draft2.txt" "$OUT_DIR/executables_from_packages_draft3.txt" "$OUT_DIR/executables_from_packages_draft4.txt"
else
  mv "$OUT_DIR/executables_from_packages_draft1.txt" "$OUT_DIR/executables_from_packages.txt"
  find /bin/ /sbin/ /usr/bin/ /usr/sbin/ -maxdepth 1 -type f | sort -T "$OUT_DIR" 2>/dev/null 1>> "$OUT_DIR/executables_present.txt"
fi
comm -2 -3 "$OUT_DIR/executables_present.txt" "$OUT_DIR/executables_from_packages.txt" 1>> "$OUT_DIR/executables_not_from_packages.txt"
cat "$OUT_DIR/executables_not_from_packages.txt" | head -n 100 1>> "$OUT_DIR/executables_not_from_packages_limit.txt" # Limit the number of files to copy, because not everything is DEB/RPM-based...
rm -f "$OUT_DIR/executables_present.txt" "$OUT_DIR/executables_from_packages.txt"
echo 'Done!'

echo 'Copying executables not from packages...'
mkdir "$OUT_DIR/binaries_not_from_packages/"
while read -r; do
  fn="$REPLY"
  [ -z "$fn" ] && continue
  cp --backup=numbered -t "$OUT_DIR/binaries_not_from_packages/" "$fn"
  md5sum "$fn" 1>>"$OUT_DIR/files_copied.md5"
done <"$OUT_DIR/executables_not_from_packages_limit.txt"
rm -f "$OUT_DIR/executables_not_from_packages_limit.txt"
echo 'Done!'

echo 'Searching for fake systemd executables...'
cat "$OUT_DIR/executables_systemd_deb.txt" "$OUT_DIR/executables_systemd_rpm.txt" | sort -T "$OUT_DIR" 2>/dev/null 1>> "$OUT_DIR/executables_systemd_deb_rpm.txt"

if [ -n "$BIN_IS_SYMLINK" ]; then
  # Still, some files are referenced through /lib/... Fix this!
  cat "$OUT_DIR/executables_systemd_deb_rpm.txt" | sed -e 's/^\/usr\//\//g' > "$OUT_DIR/executables_systemd_deb_rpm_fixed.txt"
  cat "$OUT_DIR/executables_systemd_deb_rpm.txt" | sed -e 's/^\/lib/\/usr\/lib/g' >> "$OUT_DIR/executables_systemd_deb_rpm_fixed.txt"
  cat "$OUT_DIR/executables_systemd_deb_rpm.txt" "$OUT_DIR/executables_systemd_deb_rpm_fixed.txt" | sort -T "$OUT_DIR" > "$OUT_DIR/executables_systemd_deb_rpm__.txt"
  mv "$OUT_DIR/executables_systemd_deb_rpm__.txt" "$OUT_DIR/executables_systemd_deb_rpm.txt"
  rm -f "$OUT_DIR/executables_systemd_deb_rpm_fixed.txt"
  find /usr/lib/systemd/ -maxdepth 1 -type f | sort -T "$OUT_DIR" 2>/dev/null 1>> "$OUT_DIR/executables_systemd_present.txt"
else
  find /usr/lib/systemd/ /lib/systemd/ -maxdepth 1 -type f | sort -T "$OUT_DIR" 2>/dev/null 1>> "$OUT_DIR/executables_systemd_present.txt" # Common locations!
fi
comm -2 -3 "$OUT_DIR/executables_systemd_present.txt" "$OUT_DIR/executables_systemd_deb_rpm.txt" 1>> "$OUT_DIR/executables_fake_systemd.txt"
find /var/lib/systemd/ -maxdepth 2 -type f -executable 1>> "$OUT_DIR/executables_fake_systemd.txt" # Another common location...
cat "$OUT_DIR/executables_fake_systemd.txt" | head -n 25 1>> "$OUT_DIR/executables_fake_systemd_limit.txt" # Limit the number of files to copy, just in case...
rm -f "$OUT_DIR/executables_systemd_present.txt" "$OUT_DIR/executables_fake_systemd.txt" "$OUT_DIR/executables_systemd_deb_rpm.txt"
echo 'Done!'

echo 'Copying fake systemd executables...'
mkdir "$OUT_DIR/binaries_fake_systemd/"
while read -r; do
  fn="$REPLY"
  [ -z "$fn" ] && continue
  cp --backup=numbered -t "$OUT_DIR/binaries_fake_systemd/" "$fn"
  md5sum "$fn" 1>>"$OUT_DIR/files_copied.md5"
done <"$OUT_DIR/executables_fake_systemd_limit.txt"
rm -f "$OUT_DIR/executables_fake_systemd_limit.txt"
echo 'Done!'

echo 'Scanning for suspicious command history...'
find /home/*/ /root/ -xdev -maxdepth 2 -name '*hist*' -type f -exec grep -EiaHn -A 15 -B 15 "$HISTORY_REGEX" {} \; 2>/dev/null 1>> "$OUT_DIR/hist_interesting.txt"
find /var/lib/cont* /var/lib/dock* /opt/lib/dock* /var/snap/docker -name '*hist*' -type f -exec grep -EiaHn -A 15 -B 15 "$HISTORY_REGEX" {} \; 2>/dev/null 1>> "$OUT_DIR/hist_interesting.txt"
echo 'Done!'

echo 'Dumping last 50 lines of history recorded for root...'
tail -n 50 /root/.bash_history 2>/dev/null 1> "$OUT_DIR/hist_root_last50_bash.txt"
tail -n 50 /root/.sh_history 2>/dev/null 1> "$OUT_DIR/hist_root_last50_sh.txt"
tail -n 50 /root/.python_history 2>/dev/null 1> "$OUT_DIR/hist_root_last50_python.txt"
echo 'Done!'

echo 'Scanning for less history...'
find /home/*/ /root/ -xdev -maxdepth 2 -name '.lesshst' -type f -exec grep -aH '' {} \; 2>/dev/null 1>> "$OUT_DIR/less_hst.txt"
find /home/*/ /root/ -xdev -maxdepth 2 -name 'lesshst' -type f -exec grep -aH '' {} \; 2>/dev/null 1>> "$OUT_DIR/less_hst.txt"
find /var/lib/cont* /var/lib/dock* /opt/lib/dock* /var/snap/docker -name '.lesshst' -type f -exec grep -aH '' {} \; 2>/dev/null 1>> "$OUT_DIR/less_hst.txt"
echo 'Done!'

echo 'Scanning for SSH authorized keys...'
find /home/*/ /root/ -xdev -maxdepth 3 -path '*/.ssh/authorized_keys*' -type f -exec grep -EaH '^[^#]' {} \; 2>/dev/null 1>> "$OUT_DIR/ssh_auth_keys.txt"
find /var/lib/cont* /var/lib/dock* /opt/lib/dock* /var/snap/docker -path '*/.ssh/authorized_keys*' -type f -exec grep -EaH '^[^#]' {} \; 2>/dev/null 1>> "$OUT_DIR/ssh_auth_keys.txt"
echo 'Done!'

echo 'Scanning for SSH known hosts...'
find /home/*/ /root/ -xdev -maxdepth 3 -path '*/.ssh/known_hosts*' -type f -exec grep -aH ' ' {} \; 2>/dev/null 1>> "$OUT_DIR/ssh_known_hosts.txt"
find /var/lib/cont* /var/lib/dock* /opt/lib/dock* /var/snap/docker -path '*/.ssh/known_hosts*' -type f -exec grep -aH ' ' {} \; 2>/dev/null 1>> "$OUT_DIR/ssh_known_hosts.txt"
echo 'Done!'

echo 'Scanning for wget HSTS files...'
find /home/*/ /root/ -xdev -maxdepth 5 -name '.wget-hsts*' -type f -exec grep -EaH '^[^#]' {} \; 2>/dev/null 1>> "$OUT_DIR/wget_hsts.txt"
find /var/lib/cont* /var/lib/dock* /opt/lib/dock* /var/snap/docker -name '.wget-hsts*' -type f -exec grep -EaH '^[^#]' {} \; 2>/dev/null 1>> "$OUT_DIR/wget_hsts.txt"
echo 'Done!'

echo 'Scanning for Remmina configs...'
find /home/*/ /root/ -xdev -maxdepth 5 \( -name 'remmina.pref' -o -name '*.remmina' \) -type f -exec grep -aH '' {} \; 2>/dev/null 1>> "$OUT_DIR/remmina_configs.txt"
find /var/lib/cont* /var/lib/dock* /opt/lib/dock* /var/snap/docker \(- name 'remmina.pref' -o -name '*.remmina' \) -type f -exec grep -aH '' {} \; 2>/dev/null 1>> "$OUT_DIR/remmina_configs.txt"
echo 'Done!'

echo 'Scanning for MC history...'
find /home/*/ /root/ -xdev -maxdepth 5 -path '*/mc/history' -type f -exec grep -aH '' {} \; 2>/dev/null 1>> "$OUT_DIR/mc_history.txt"
find /var/lib/cont* /var/lib/dock* /opt/lib/dock* /var/snap/docker -path '*/mc/history' -type f -exec grep -aH '' {} \; 2>/dev/null 1>> "$OUT_DIR/mc_history.txt"
echo 'Done!'

echo 'Scanning for vim info...'
find /home/*/ /root/ -xdev -maxdepth 5 -name '.viminfo' -type f -exec grep -aH '' {} \; 2>/dev/null 1>> "$OUT_DIR/vim_viminfo.txt"
find /var/lib/cont* /var/lib/dock* /opt/lib/dock* /var/snap/docker -name '.viminfo' -type f -exec grep -aH '' {} \; 2>/dev/null 1>> "$OUT_DIR/vim_viminfo.txt"
find /home/*/ /root/ -xdev -maxdepth 5 -path '*/.vim/.netrwhist' -type f -exec grep -aH '' {} \; 2>/dev/null 1>> "$OUT_DIR/vim_netrwhist.txt"
find /var/lib/cont* /var/lib/dock* /opt/lib/dock* /var/snap/docker -path '*/.vim/.netrwhist' -type f -exec grep -aH '' {} \; 2>/dev/null 1>> "$OUT_DIR/vim_netrwhist.txt"
echo 'Done!'

echo 'Scanning for XDG autostart files...'
find /home/*/ /root/ -xdev -maxdepth 5 -path '*/.config/autostart/*.desktop' -type f -exec grep -aH '' {} \; 2>/dev/null 1>> "$OUT_DIR/xdg_autostart.txt"
find /var/lib/cont* /var/lib/dock* /opt/lib/dock* /var/snap/docker -path '*/.config/autostart/*.desktop' -type f -exec grep -aH '' {} \; 2>/dev/null 1>> "$OUT_DIR/xdg_autostart.txt"
echo 'Done!'

echo 'Running lsof...'
lsof -nPl 2>/dev/null | gzip -3 1>"$OUT_DIR/lsof-nPl.txt.gz"
echo 'Done!'

echo 'Dumping BPF programs...'
mkdir "$OUT_DIR/bpf_dumped/"
for name in $(cat "$OUT_DIR/bpftool_prog_list.txt" | grep -Eo ' name .+' | cut -d ' ' -f 3 | sort | uniq); do
  [ -z "$name" ] && continue
  printf '%s\n' " $name"
  name_sane=$(printf '%s\n' "$name" | sed -e 's/\//_/g' -e 's/[[:space:]]/_/g')
  bpftool prog dump xlated name "$name" 1>>"$OUT_DIR/bpf_dumped/$name_sane.txt"
  echo '[dump end]' 1>>"$OUT_DIR/bpf_dumped/$name_sane.txt"
done
echo 'Done!'

echo 'Packing some large text files...'
gzip -2 "$OUT_DIR/file_suid_sgid.txt"
gzip -2 "$OUT_DIR/executables_deb.txt"
gzip -2 "$OUT_DIR/executables_rpm.txt"
gzip -2 "$OUT_DIR/executables_not_from_packages.txt"
echo 'Done!'

do_internet=$(echo "$TRIAGE_OPTIONS" | grep -wo 'internet')
if [ "$do_internet" = 'internet' ]; then
  echo 'Checking basic Internet connectivity (ping and icanhazip)...'
  ping -n -c 3 8.8.8.8 1>"$OUT_DIR/ping_8_8_8_8.txt"
  ping6 -n -c 3 google.com 1>"$OUT_DIR/ping6_google_com.txt"

  which wget 1>/dev/null 2>/dev/null
  if [ $? -eq 0 ]; then
    wget --tries=1 -S -O - http://icanhazip.com/ 1>"$OUT_DIR/web_icanhazip.txt" 2>&1
  else
    which curl 1>/dev/null 2>/dev/null
    if [ $? -eq 0 ]; then
      curl --retry 1 -i http://icanhazip.com/ 1>"$OUT_DIR/web_icanhazip.txt" 2>&1
    fi
  fi
  echo 'Done!'

  echo 'Local date & time:' 1>"$OUT_DIR/time_shift.txt"
  date 1>>"$OUT_DIR/time_shift.txt"
  echo 'Internet date & time:' 1>>"$OUT_DIR/time_shift.txt"
  cat "$OUT_DIR/web_icanhazip.txt" | grep -F -m 1 'Date:' 1>>"$OUT_DIR/time_shift.txt"
fi

echo 'Dumping locate database...'
locate '' 2>/dev/null | gzip -4 1>> "$OUT_DIR/locate_paths.txt.gz"
echo 'Done!'

echo 'Searching for deleted but running executables...'
find /proc -maxdepth 2 -path '*/exe' -printf '%p\t' -exec bash -c 'readlink -n {} ; echo' \; 2>/dev/null | grep -F '(deleted)' 1>> "$OUT_DIR/orphan_executables.txt"
cat "$OUT_DIR/orphan_executables.txt"
echo 'Done!'

echo 'Dumping output from physical consoles...'
mkdir "$OUT_DIR/phy_cons/"
for i in $(seq 1 9); do # Dumping output from "forgotten" physical consoles...
  setterm -dump "$i" -file "$OUT_DIR/phy_cons/$i.txt" 2>/dev/null
  term_output_present=$(grep -E '(\$|#|>>>)($|( )+(\.|/|[[:alpha:]]))' "$OUT_DIR/phy_cons/$i.txt" 2>/dev/null) # There is a shell prompt (or something like that)...
  term_output_check=$(grep -E '(dumping output from physical consoles)|easy_triage' "$OUT_DIR/phy_cons/$i.txt" 2>/dev/null) # And there is no our output (see the 'echo' command above)!
  if [ -n "$term_output_present" -a -z "$term_output_check" ]; then
    echo " note: console $i contains interpreter!"

    which perl 1>/dev/null 2>/dev/null
    if [ $? -eq 0 -a $i -eq 1 ]; then # Do not dump the history for physical consoles other than the first one.
      for j in $(seq 1 32); do
        # Send the "up" key (HEX: 1B 5B 41) to the console and dump the output, then repeat.
        # Hopefully, simply sending the "up" key to the console will not do anything unwanted...
        perl -e 'open(my $con, "<", "/dev/tty1"); $char="\x1b"; ioctl($con, 0x5412, $char); $char="\x5b"; ioctl($con, 0x5412, $char); $char="\x41"; ioctl($con, 0x5412, $char);'
        setterm -dump 1 -file "$OUT_DIR/phy_cons/1_keyup_$j.txt" 2>/dev/null
      done
    fi
  fi
done
echo 'Done!'

# Deleted but running executables are still present on the disk (as orphan files: i.e., unlinked from the directory tree but allocated).
# We dump such executables from from the file system ('*.fs_bin'), if possible, and from the memory ('*.mem_bin').
#
# NOTE: dumping a process from the memory can kill THAT process (by bringing swapped pages back into the resident set of THE TARGET PROCESS)!
# So, the OOM killer can terminate an important process when we dump its memory (and OUR process will survive).
# (Reference: <https://github.com/VirusTotal/yara/issues/1620>.)
# Account that by limiting the amount of bytes read: i.e., no more than 16 MiB (soft limit, though); also, stick to memory ranges with the backing file in question...

do_orphan=$(echo "$TRIAGE_OPTIONS" | grep -wo 'orphan')

# Do not do anything, if there is no Python...
echo -n ' (Searching for Python... '
best_python=''
for python in python3 python2 python; do
  echo -n "$python "
  which $python 1>/dev/null 2>/dev/null
  if [ $? -eq 0 ]; then
    echo ' found!)'
    best_python=$(which $python 2>/dev/null)
    break
  fi
done

if [ -z "$best_python" ]; then
  echo ' not found :-( )'
  do_orphan=''
fi

# Helper script:
echo '#!/usr/bin/env python' 1>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo 'from __future__ import print_function' 1>>"$OUT_DIR/dump_exe.py"
echo 'import sys' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo 'SIZE_LIMIT = 16*1024*1024' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo 'exe = sys.argv[1]' 1>>"$OUT_DIR/dump_exe.py"
echo 'try:' 1>>"$OUT_DIR/dump_exe.py"
echo '  maps = open(sys.argv[2], "r").read().splitlines()' 1>>"$OUT_DIR/dump_exe.py"
echo '  mem = open(sys.argv[3], "rb")' 1>>"$OUT_DIR/dump_exe.py"
echo '  out = open(sys.argv[4], "wb")' 1>>"$OUT_DIR/dump_exe.py"
echo 'except Exception: # Invalid arguments or not enough permissions' 1>>"$OUT_DIR/dump_exe.py"
echo '  print("USAGE ERROR: invalid arguments or not enough permissions")' 1>>"$OUT_DIR/dump_exe.py"
echo '  sys.exit(1)' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo 'known_major_minor = None' 1>>"$OUT_DIR/dump_exe.py"
echo 'known_inode = None' 1>>"$OUT_DIR/dump_exe.py"
echo 'bytes_written = 0' 1>>"$OUT_DIR/dump_exe.py"
echo 'warned_about_offsets = False' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo 'for mapping in maps:' 1>>"$OUT_DIR/dump_exe.py"
echo '  if mapping.endswith(" " + exe):' 1>>"$OUT_DIR/dump_exe.py"
echo '    mem_range, perms, file_offset, major_minor, inode = mapping.split(" ")[:5]' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    if not perms.startswith("r"): # Not a readable range, skip it.' 1>>"$OUT_DIR/dump_exe.py"
echo '      continue' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    if major_minor.startswith("00:") or major_minor.startswith("0:"): # Skip null devices.' 1>>"$OUT_DIR/dump_exe.py"
echo '      continue' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    if known_major_minor is None:' 1>>"$OUT_DIR/dump_exe.py"
echo '      known_major_minor = major_minor' 1>>"$OUT_DIR/dump_exe.py"
echo '    elif known_major_minor != major_minor: # The same path, but in another file system, skip it.' 1>>"$OUT_DIR/dump_exe.py"
echo '      continue' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    if known_inode is None:' 1>>"$OUT_DIR/dump_exe.py"
echo '      known_inode = inode' 1>>"$OUT_DIR/dump_exe.py"
echo '    elif known_inode != inode: # The same path, but a different inode, skip it.' 1>>"$OUT_DIR/dump_exe.py"
echo '      continue' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    mem_start, mem_end = mem_range.split("-")' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    try:' 1>>"$OUT_DIR/dump_exe.py"
echo '      mem_start = int(mem_start, base = 16)' 1>>"$OUT_DIR/dump_exe.py"
echo '      mem_end = int(mem_end, base = 16)' 1>>"$OUT_DIR/dump_exe.py"
echo '      file_offset = int(file_offset, base = 16)' 1>>"$OUT_DIR/dump_exe.py"
echo '    except Exception:' 1>>"$OUT_DIR/dump_exe.py"
echo '      print("BUG: invalid integer(s) in mapping")' 1>>"$OUT_DIR/dump_exe.py"
echo '      print(mapping)' 1>>"$OUT_DIR/dump_exe.py"
echo '      break' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    mem_length = mem_end - mem_start' 1>>"$OUT_DIR/dump_exe.py"
echo '    if mem_length < 4096 or mem_length % 4096 != 0: # Invalid "address start - address end" definition or page size is smaller than 4096 bytes.' 1>>"$OUT_DIR/dump_exe.py"
echo '      print("BUG: invalid memory range in mapping")' 1>>"$OUT_DIR/dump_exe.py"
echo '      print(mapping)' 1>>"$OUT_DIR/dump_exe.py"
echo '      break' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    if mem_length > SIZE_LIMIT:' 1>>"$OUT_DIR/dump_exe.py"
echo '      mem_length = SIZE_LIMIT' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    if bytes_written != file_offset and not warned_about_offsets: # Typically, mapped ranges and file offsets will be in order.' 1>>"$OUT_DIR/dump_exe.py"
echo '      print("WARNING: unusual offsets")' 1>>"$OUT_DIR/dump_exe.py"
echo '      print(mapping)' 1>>"$OUT_DIR/dump_exe.py"
echo '      warned_about_offsets = True' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    mem.seek(mem_start)' 1>>"$OUT_DIR/dump_exe.py"
echo '    if mem.tell() != mem_start: # Starting offset is out-of-range for some reason.' 1>>"$OUT_DIR/dump_exe.py"
echo '      print("BUG: cannot seek to memory range start")' 1>>"$OUT_DIR/dump_exe.py"
echo '      print(mapping)' 1>>"$OUT_DIR/dump_exe.py"
echo '      break' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    out.seek(file_offset)' 1>>"$OUT_DIR/dump_exe.py"
echo '    if out.tell() != file_offset: # Likely a file system error.' 1>>"$OUT_DIR/dump_exe.py"
echo '      print("FS ERROR: cannot seek in output file")' 1>>"$OUT_DIR/dump_exe.py"
echo '      print(mapping)' 1>>"$OUT_DIR/dump_exe.py"
echo '      break' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    buf = mem.read(mem_length)' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    if len(buf) != mem_length: # Ending offset is out-of-range for some reason.' 1>>"$OUT_DIR/dump_exe.py"
echo '      print("BUG: cannot read bytes from memory range")' 1>>"$OUT_DIR/dump_exe.py"
echo '      print(mapping)' 1>>"$OUT_DIR/dump_exe.py"
echo '      break' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    out.write(buf)' 1>>"$OUT_DIR/dump_exe.py"
echo '    if out.tell() != file_offset + len(buf): # Likely a file system error.' 1>>"$OUT_DIR/dump_exe.py"
echo '      print("FS ERROR: cannot write to output file")' 1>>"$OUT_DIR/dump_exe.py"
echo '      print(mapping)' 1>>"$OUT_DIR/dump_exe.py"
echo '      break' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    bytes_written += mem_length' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo '    if bytes_written > SIZE_LIMIT:' 1>>"$OUT_DIR/dump_exe.py"
echo '      break' 1>>"$OUT_DIR/dump_exe.py"
echo '' 1>>"$OUT_DIR/dump_exe.py"
echo 'mem.close()' 1>>"$OUT_DIR/dump_exe.py"
echo 'out.close()' 1>>"$OUT_DIR/dump_exe.py"

if [ "$do_orphan" = 'orphan' ]; then
  orphan_count=$(cat "$OUT_DIR/orphan_executables.txt" | wc -l)
  if [ $orphan_count -ne 0 ]; then # If there are no orphan executables, there is nothing to do...
    mkdir "$OUT_DIR/binaries_orphan/"
    while read -r; do
        line="$REPLY"
        [ -z "$line" ] && continue

        mem_file=$(printf '%s\n' "$line" | cut -d '	' -f 1 | sed -e 's/\/exe$/\/mem/')
        maps_file=$(printf '%s\n' "$line" | cut -d '	' -f 1 | sed -e 's/\/exe$/\/maps/')
        exe_file=$(printf '%s\n' "$line" | cut -d '	' -f 2-)
        exe_symlink=$(printf '%s\n' "$line" | cut -d '	' -f 1)
        out_base=$(printf '%s\n' "$exe_file" | sed -e 's/\//_/g' -e 's/[[:space:]]/_/g')

        # Do not overwrite an existing file, but (also) do not write more than two instances (copies) of the file.
        # At most 2 files sharing the same path will be stored.
        [ -e "$OUT_DIR/binaries_orphan/$out_base.txt" ] && out_base=$(printf '%s_another\n' "$out_base")

        stat -L "$exe_symlink" 1>"$OUT_DIR/binaries_orphan/$out_base.txt"
        dd if="$exe_symlink" bs=1M count=32 of="$OUT_DIR/binaries_orphan/$out_base.fs_bin" 2>/dev/null # In the memory dumper, the limit is lower.
        echo " copied as file: $exe_symlink"

        cat "$maps_file" 1> "$OUT_DIR/binaries_orphan/$out_base.mem_map"
        echo " launching: $best_python \"$OUT_DIR/dump_exe.py\" \"$exe_file\" \"$maps_file\" \"$mem_file\" \"$OUT_DIR/binaries_orphan/$out_base.mem_bin\""
        "$best_python" "$OUT_DIR/dump_exe.py" "$exe_file" "$maps_file" "$mem_file" "$OUT_DIR/binaries_orphan/$out_base.mem_bin"
    done <"$OUT_DIR/orphan_executables.txt"
  fi
fi

# Okay, let's try to catch some rootkits (e.g., Reptile and its derivatives) trying to hide PIDs in /proc!
# We also need Python for this...

do_rootkit=$(echo "$TRIAGE_OPTIONS" | grep -wo 'rootkit')

# Helper script:
echo '#!/usr/bin/env python' 1>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo 'from __future__ import print_function' 1>>"$OUT_DIR/scan_pids.py"
echo 'import os' 1>>"$OUT_DIR/scan_pids.py"
echo 'import time' 1>>"$OUT_DIR/scan_pids.py"
echo 'import subprocess' 1>>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo 'PID_LIMIT = 0x1000000' 1>>"$OUT_DIR/scan_pids.py"
echo 'TIME_LIMIT = 1200' 1>>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo 'pid_start = 2' 1>>"$OUT_DIR/scan_pids.py"
echo 'pid_end = int(open("/proc/sys/kernel/pid_max", "r").read())' 1>>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo 'if pid_end > PID_LIMIT:' 1>>"$OUT_DIR/scan_pids.py"
echo '  pid_end = PID_LIMIT' 1>>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo 'time_start = time.time()' 1>>"$OUT_DIR/scan_pids.py"
echo 'for pid in range(pid_start, pid_end + 1):' 1>>"$OUT_DIR/scan_pids.py"
echo '  if time.time() - time_start > TIME_LIMIT:' 1>>"$OUT_DIR/scan_pids.py"
echo '    break' 1>>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo '  pid = str(pid)' 1>>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo '  check_readdir_1 = pid in os.listdir("/proc")' 1>>"$OUT_DIR/scan_pids.py"
echo '  try:' 1>>"$OUT_DIR/scan_pids.py"
echo '    stat_11 = os.stat("/proc/" + pid )' 1>>"$OUT_DIR/scan_pids.py"
echo '    stat_12 = os.stat("/proc/" + pid + "/exe")' 1>>"$OUT_DIR/scan_pids.py"
echo '    cmd_1 = os.readlink(b"/proc/" + pid.encode() + b"/exe")' 1>>"$OUT_DIR/scan_pids.py"
echo '  except OSError:' 1>>"$OUT_DIR/scan_pids.py"
echo '    continue' 1>>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo '  check_readdir_2 = pid in os.listdir("/proc")' 1>>"$OUT_DIR/scan_pids.py"
echo '  try:' 1>>"$OUT_DIR/scan_pids.py"
echo '    stat_21 = os.stat("/proc/" + pid)' 1>>"$OUT_DIR/scan_pids.py"
echo '    stat_22 = os.stat("/proc/" + pid + "/exe")' 1>>"$OUT_DIR/scan_pids.py"
echo '    cmd_2 = os.readlink(b"/proc/" + pid.encode() + b"/exe")' 1>>"$OUT_DIR/scan_pids.py"
echo '  except OSError:' 1>>"$OUT_DIR/scan_pids.py"
echo '    continue' 1>>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo '  if (not check_readdir_1) and (not check_readdir_2) and stat_11 == stat_21 and stat_12 == stat_22 and cmd_1 == cmd_2:' 1>>"$OUT_DIR/scan_pids.py"
echo '    pid_status_lines = open("/proc/" + pid + "/status", "r").read().splitlines()' 1>>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo '    status_tgid = None' 1>>"$OUT_DIR/scan_pids.py"
echo '    status_pid = None' 1>>"$OUT_DIR/scan_pids.py"
echo '    for pid_status_line in pid_status_lines:' 1>>"$OUT_DIR/scan_pids.py"
echo '      if pid_status_line.startswith("Tgid:"):' 1>>"$OUT_DIR/scan_pids.py"
echo '        status_tgid = pid_status_line[len("Tgid:") :].lstrip()' 1>>"$OUT_DIR/scan_pids.py"
echo '      ' 1>>"$OUT_DIR/scan_pids.py"
echo '      if pid_status_line.startswith("Pid:"):' 1>>"$OUT_DIR/scan_pids.py"
echo '        status_pid = pid_status_line[len("Pid:") :].lstrip()' 1>>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo '      if status_tgid is not None and status_pid is not None:' 1>>"$OUT_DIR/scan_pids.py"
echo '        break' 1>>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo '    if status_pid is None or status_tgid is None or len(status_pid) == 0 or len(status_tgid) == 0:' 1>>"$OUT_DIR/scan_pids.py"
echo '      continue' 1>>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo '    if status_pid != status_tgid:' 1>>"$OUT_DIR/scan_pids.py"
echo '      continue' 1>>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo '    cmd = cmd_1.decode("utf-8", errors = "replace")' 1>>"$OUT_DIR/scan_pids.py"
echo '' 1>>"$OUT_DIR/scan_pids.py"
echo '    print("Hidden PID: " + pid)' 1>>"$OUT_DIR/scan_pids.py"
echo '    print(" cmd=" + cmd)' 1>>"$OUT_DIR/scan_pids.py"
echo '    print("PID info:")' 1>>"$OUT_DIR/scan_pids.py"
echo '    subprocess.call(["ls", "-l", "--full-time", "/proc/" + pid + "/"])' 1>>"$OUT_DIR/scan_pids.py"
echo '    print("PID FDs:")' 1>>"$OUT_DIR/scan_pids.py"
echo '    subprocess.call(["ls", "-l", "--full-time", "/proc/" + pid + "/fd/"])' 1>>"$OUT_DIR/scan_pids.py"
echo '    print("PID TCP:")' 1>>"$OUT_DIR/scan_pids.py"
echo '    subprocess.call(["cat", "/proc/" + pid + "/net/tcp"])' 1>>"$OUT_DIR/scan_pids.py"
echo '    print("PID TCP6:")' 1>>"$OUT_DIR/scan_pids.py"
echo '    subprocess.call(["cat", "/proc/" + pid + "/net/tcp6"])' 1>>"$OUT_DIR/scan_pids.py"
echo '    print("PID UDP:")' 1>>"$OUT_DIR/scan_pids.py"
echo '    subprocess.call(["cat", "/proc/" + pid + "/net/udp"])' 1>>"$OUT_DIR/scan_pids.py"
echo '    print("PID UDP6:")' 1>>"$OUT_DIR/scan_pids.py"
echo '    subprocess.call(["cat", "/proc/" + pid + "/net/udp6"])' 1>>"$OUT_DIR/scan_pids.py"
echo '    print("---")' 1>>"$OUT_DIR/scan_pids.py"

if [ -n "$best_python" -a "$do_rootkit" = 'rootkit' ]; then
  echo 'Searching for hidden PIDs (limit is 20 mins)...'
  echo " launching: $best_python \"$OUT_DIR/scan_pids.py\""
  "$best_python" -u "$OUT_DIR/scan_pids.py" 1>> "$OUT_DIR/scan_pids.txt"
  echo 'Done!'

  mkdir "$OUT_DIR/binaries_rootkit"
  grep -E '^ cmd=' "$OUT_DIR/scan_pids.txt" | cut -d '=' -f 2- 1>"$OUT_DIR/scan_pids_exes.txt"
  grep -E '^Hidden PID: ' "$OUT_DIR/scan_pids.txt" | cut -d ' ' -f 3 1>"$OUT_DIR/scan_pids_pids.txt"

  # Now, dump their executables using two methods.

  # Dump by file system path.
  while read -r; do
    fn="$REPLY"
    [ -z "$fn" ] && continue

    fn_out=$(printf '%s\n' "$fn" | sed -e 's/\//_/g' -e 's/[[:space:]]/_/g')
    stat "$fn" 1> "$OUT_DIR/binaries_rootkit/$fn_out.txt"
    dd if="$fn" bs=1M count=16 of="$OUT_DIR/binaries_rootkit/$fn_out.fs_bin_by_path" 2>/dev/null
  done <"$OUT_DIR/scan_pids_exes.txt"

  # Dump from '/proc/<pid>/exe'.
  while read -r; do
    pid="$REPLY"
    [ -z "$pid" ] && continue

    dd if=/proc/"$pid"/exe bs=1M count=16 of="$OUT_DIR/binaries_rootkit/$pid.fs_bin_by_pid" 2>/dev/null
  done <"$OUT_DIR/scan_pids_pids.txt"
fi

do_qemu=$(echo "$TRIAGE_OPTIONS" | grep -wo 'qemu')

if [ "$do_qemu" = 'qemu' ]; then
  # Try to find a suspicious QEMU VM.
  # Running one VM in the "headless" mode is suspicious if no serial port is given and either a virtual disk or a socket connection is present.
  # Running two or more of such VMs isn't suspicious, but we record their PIDs for further investigation.
  echo 'Searching for suspicious QEMU VMs...'
  ps -e -o pid,cmd -w -w | grep -E -- ' -(nographic|display( )+none)($| )' | grep -Fv -- ' -serial ' | grep -E -- '(-hda|-hdb|-hdc|-hdd|-cdrom|file=|connect=)' | awk '{ print $1 }' 1>>"$OUT_DIR/qemu_suspicious_pids.txt"
  qemu_pids_count=$(wc -l "$OUT_DIR/qemu_suspicious_pids.txt" | cut -d ' ' -f 1)
  if [ $qemu_pids_count -eq 1 ]; then
    qemu_pid=$(cat "$OUT_DIR/qemu_suspicious_pids.txt" | head -n 1)
    echo " found PID: $qemu_pid"

    readlink -e /proc/"$qemu_pid"/fd/* 1>>"$OUT_DIR/qemu_fds.txt"
    while read -r; do
      fn="$REPLY"
      [ -n "$fn" -a -f "$fn" -a -r "$fn" ] || continue

      is_disk_image=$(file -b "$fn" | grep -Ei '(disk image)|(qcow image)|(boot sector)|(iso 9660)') # Check if this is a disk image...
      [ -n "$is_disk_image" ] || continue

      echo " found disk image: $fn"
      printf '%s\n' "$fn" 1>>"$OUT_DIR/qemu_suspicious_disks.txt"

      # Copy the first 64 MiB of that image (using the sparse mode and direct I/O)... And skip any other images (i.e., copy only the first one).
      # (For reference: the Tiny Core Linux image is 24 MiB, so 64 MiB should be enough.)
      if [ ! -f "$OUT_DIR/qemu_suspicious_disk.bin" ]; then
        dd if="$fn" of="$OUT_DIR/qemu_suspicious_disk.bin" bs=1024 count=65536 iflag=direct conv=sparse 2>/dev/null
        echo ' copied it'
        printf '%s\n' "copied: $fn" 1>>"$OUT_DIR/qemu_suspicious_disks.txt"
      fi
    done <"$OUT_DIR/qemu_fds.txt"
    rm -f "$OUT_DIR/qemu_fds.txt"
  fi
  echo 'Done!'
fi

# Find overmounted /proc/<pid>/ directories...
do_omproc=$(echo "$TRIAGE_OPTIONS" | grep -wo 'omproc')

if [ "$do_omproc" = 'omproc' ]; then
  echo 'Searching for overmounted /proc/<pid>/...'

  # If there are more than 10 of overmounted PIDs, something is wrong with this system.
  # Never try to deal with more than 10 of such PIDs...
  cat "$OUT_DIR/mounts.txt" | grep -E '^proc /proc/[[:digit:]]{1,} proc ' | head -n 10 | cut -d ' ' -f 2 | cut -d '/' -f 3 | sort | uniq 1>>"$OUT_DIR/overmounted_pids.txt"
  if [ -s "$OUT_DIR/overmounted_pids.txt" ]; then
    mkdir "$OUT_DIR/new_proc/"
    mkdir "$OUT_DIR/overmounted_pids/"

    mount -t proc none "$OUT_DIR/new_proc/"
    sleep 1

    while read -r; do
      pid="$REPLY"
      [ -z "$pid" ] && continue
      echo " found PID: $pid"

      echo 'PID info:' 1>>"$OUT_DIR/overmounted_pids/$pid.txt"
      ls -l --full-time "$OUT_DIR/new_proc/$pid/" 1>>"$OUT_DIR/overmounted_pids/$pid.txt"
      echo '---' 1>>"$OUT_DIR/overmounted_pids/$pid.txt"

      echo 'PID FDs:' 1>>"$OUT_DIR/overmounted_pids/$pid.txt"
      ls -l --full-time "$OUT_DIR/new_proc/$pid/fd/" 1>>"$OUT_DIR/overmounted_pids/$pid.txt"
      echo '---' 1>>"$OUT_DIR/overmounted_pids/$pid.txt"

      echo 'PID TCP:' 1>>"$OUT_DIR/overmounted_pids/$pid.txt"
      cat "$OUT_DIR/new_proc/$pid/net/tcp" 1>>"$OUT_DIR/overmounted_pids/$pid.txt"
      echo '---' 1>>"$OUT_DIR/overmounted_pids/$pid.txt"

      echo 'PID TCP6:' 1>>"$OUT_DIR/overmounted_pids/$pid.txt"
      cat "$OUT_DIR/new_proc/$pid/net/tcp6" 1>>"$OUT_DIR/overmounted_pids/$pid.txt"
      echo '---' 1>>"$OUT_DIR/overmounted_pids/$pid.txt"

      echo 'PID UDP:' 1>>"$OUT_DIR/overmounted_pids/$pid.txt"
      cat "$OUT_DIR/new_proc/$pid/net/udp" 1>>"$OUT_DIR/overmounted_pids/$pid.txt"
      echo '---' 1>>"$OUT_DIR/overmounted_pids/$pid.txt"

      echo 'PID UDP6:' 1>>"$OUT_DIR/overmounted_pids/$pid.txt"
      cat "$OUT_DIR/new_proc/$pid/net/udp6" 1>>"$OUT_DIR/overmounted_pids/$pid.txt"
      echo '---' 1>>"$OUT_DIR/overmounted_pids/$pid.txt"

      mkdir "$OUT_DIR/binaries_rootkit" 2>/dev/null
      dd if="$OUT_DIR/new_proc/$pid"/exe bs=1M count=16 of="$OUT_DIR/binaries_rootkit/$pid.fs_bin_by_ompid" 2>/dev/null
    done <"$OUT_DIR/overmounted_pids.txt"

    sleep 3
    umount "$OUT_DIR/new_proc/" && rmdir "$OUT_DIR/new_proc/"
    sleep 4
    umount "$OUT_DIR/new_proc/" 2>/dev/null && rmdir "$OUT_DIR/new_proc/" 2>/dev/null
  fi

  echo 'Done!'
fi

# Trace network activity of suspicious processes...
do_strace=$(echo "$TRIAGE_OPTIONS" | grep -wo 'strace')

# Check that we have the 'timeout' program...
if [ "$do_strace" = 'strace' ]; then
  which timeout 1>/dev/null 2>/dev/null
  if [ $? -ne 0 ]; then
    echo 'timeout not found! Skipping the strace... :-('
    do_strace=''
  fi
fi

# Check that we are running as root...
if [ "$do_strace" = 'strace' ]; then
  if [ $EUID -ne 0 ]; then
    echo 'Not running as root! Skipping the strace...'
    do_strace=''
  fi
fi

# Check that we have the 'strace' program.
# If not, try to install it...
if [ "$do_strace" = 'strace' ]; then
  which strace 1>/dev/null 2>/dev/null
  if [ $? -ne 0 ]; then
    # No 'strace', let's try to install it...

    echo 'Trying to install strace, through apt-get...'
    apt-get -y install strace
    which strace 1>/dev/null 2>/dev/null

    if [ $? -ne 0 ]; then
      echo 'Trying to install strace, through dnf...'
      dnf -y install strace
      which strace 1>/dev/null 2>/dev/null

      if [ $? -ne 0 ]; then
        echo 'Trying to install strace, through yum...'
        yum -y install strace
        which strace 1>/dev/null 2>/dev/null

        if [ $? -ne 0 ]; then
          echo 'strace not found and cannot be installed! Skipping the strace... :-('
          do_strace=''
        fi
      fi
    fi
  fi
fi

# Do the trace!
if [ "$do_strace" = 'strace' ]; then
  # Locate suspicious processes...

  # 'sshd' that (probably) failed the hash check, 1 process.
  if [ -s "$OUT_DIR/binaries_failed/sshd" ]; then
    pids1=$(ps -e -o pid,comm -w -w | grep -E ' sshd$' | head -n 1 | awk '{ print $1 }')
  fi

  # 'python' that runs without arguments, 2 processes.
  pids2=$(ps -e -o pid,cmd -w -w | grep -E '( |/)python(|2|3)$' | tail -n 2 | awk '{ print $1 }')
  if [ -z "$pids2" ]; then
    # Or 'python -i', or 'python -u', 'python -q'... 1 process.
    pids2=$(ps -e -o pid,cmd -w -w | grep -E '( |/)python(|2|3)[[:space:]]{1,5}(-i|-u|-q)[[:space:]]{0,5}$' | head -n 1 | awk '{ print $1 }')
  fi

  # And some running programs that (probably) are not from packages. 2 processes.
  # Stick to "simple" names (containing only alphanumeric characters and any of these: '_', '.', '-').
  # Also, exclude ambiguous names ('COMMAND') and, hopefully, VMware processes (start with 'vm') and QEMU processes ('qemu').
  pids3=$(find "$OUT_DIR/binaries_not_from_packages/" -type f -printf '%f\n' | grep -E '^([[:alnum:]]|[_\.-]){4,}$' | grep -Ev '(^COMMAND$|^vm|^qemu)' | sed -e 's/\./\\./g' | xargs -I '{}' bash -c "ps -e -o pid,comm -w -w | grep -E ' {}$'" | head -n 2 | awk '{ print $1 }' | tr '\n' ',')

  pids=$(echo "$pids1,$pids2,$pids3" | sed -e 's/,,/,/g' -e 's/^,//g' -e 's/,$//g')

  # And do it!
  if [ -n "$pids" ]; then
    echo "Running strace for PIDs: $pids (limit is 3 mins)..."
    timeout --kill-after=40s --signal=SIGINT 180s strace --string-limit=64 --absolute-timestamps -e "$STRACE_FILTER" --attach="$pids" 2>&1 | gzip -2 1>> "$OUT_DIR/straces.txt.gz"
    echo 'Done!'
  fi
fi

# This should be the last action performed (it can create some memory pressure)...
do_swap=$(echo "$TRIAGE_OPTIONS" | grep -wo 'swap')

which strings 1>/dev/null 2>/dev/null
if [ $? -ne 0 ]; then
  test_str=$(echo '123' | busybox strings -n 3 2>/dev/null | grep -E '^123$')
  if [ -n "$test_str" ]; then # There is no 'strings', but there is 'busybox strings'!
    best_strings='busybox strings'
  else
    echo 'strings not found :-('
    do_swap=''
    best_strings=''
  fi
else
  best_strings='strings'
fi

if [ "$do_swap" = 'swap' ]; then
  echo 'Trying to carve interesting strings from swap space...'

  swap_dev=$(swapon --noheadings --show=NAME 2>/dev/null | grep -v ram | head -n 1)
  if [ -z "$swap_dev" ]; then
    swap_dev=$(swapon -s | grep -Ev '(^Filename)|ram' | cut -d ' ' -f 1 | head -n 1)
  fi

  if [ -n "$swap_dev" -a -r "$swap_dev" ]; then
    printf '%s\n' " $swap_dev"
    # This will never read more than 7 GiB of swap space (and from no more than one device/file, excluding compressed RAM), never produce more than 800 lines.
    # Use direct I/O to reduce the cache usage. If that mode is unavailable, bail out!
    dd if="$swap_dev" bs=1024 iflag=direct count=7340032 2>/dev/null | $best_strings -n 10 | grep -A 5 -B 5 'Accepted ' | head -n 800 | gzip -7 1>> "$OUT_DIR/swap_carved.txt.gz"
  fi
  echo 'Done!'
fi

echo 'Finalizing and packing results...'
echo "$TOOL_VERSION" 1>"$OUT_DIR/easy_triage_version.txt"
rm -f "$OUT_FILE"
tar cvSjf "$OUT_FILE" "$OUT_DIR" 1>/dev/null 2>/dev/null || tar zvScf "$OUT_FILE" "$OUT_DIR" 1>/dev/null
[ -r "$OUT_DIR/check_file.sh" -a -r "$OUT_DIR/easy_triage_version.txt" ] && rm -fr "$OUT_DIR"
echo 'Done!'

echo 'All done!'
echo "$OUT_FILE"
