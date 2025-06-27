Network Mapping & Vulnerability Identification

Scheduled internal port scans
nmap -sT -p- -oA /tmp/internal_scan 192.168.0.0/24

Find rogue DHCP servers using dhcpdump
dhcpdump -i eth0 | grep -i 'server identifier'

Auto-report unauthenticated services via OpenVAS
omp -u admin -w 'pass' -T 'unauthenticated' -F xml -o scan.xml && curl -F 'file=@scan.xml' https://reporting.example.com/

Map lateral paths with ARP and MAC tables
arp -a && ip link show && brctl showmacs br0

Detect new MACs on trusted interfaces
ip neigh | grep REACHABLE | cut -d' ' -f1 | uniq -c | sort -nr

Detect DNS leaks and proxy bypasses
curl ifconfig.me && dig TXT o-o.myaddr.l.google.com @ns1.google.com +short

Isolate hosts hitting malicious IPs
grep -E '198\.51\.100\.' /var/log/syslog | awk '{print $5}' | uniq | xargs -I{} iptables -I FORWARD -s {} -j DROP

Detect outbound HTTP shells
tcpdump -i eth0 -A | grep -Ei 'cmd=|bash|curl'

Re-check TLS configs using ssllabs-scan
ssllabs-scan --quiet www.example.com | grep -i 'grade'

Log login attempts from TOR exit nodes
grep 'Accepted' /var/log/auth.log | awk '{print $(NF-3)}' | xargs -I{} curl https://check.torproject.org/exit-addresses | grep {}

 Visualization, Reporting & Behavior Tracking

Create login source heatmap
awk '{print $1}' /var/log/auth.log | sort | uniq -c > /tmp/logins.txt && python heatmap.py /tmp/logins.txt

Weekly threat summary by category
grep 'Ban\|Fail\|Blocked' /var/log/* | awk '{print $NF}' | sort | uniq -c | sort -nr > /tmp/weekly_threats.txt

Correlate bandwidth spikes with auth logs
iftop -nP -t -s 60 | tee /tmp/net_top.txt && grep 'Failed' /var/log/auth.log | tail -n 50

Visualize CPU usage vs users
ps -eo user,%cpu --sort=-%cpu | head | gnuplot -p -e "plot '/dev/stdin' using 2:xtic(1) with boxes"

Map attacker behavior in kill-chain format
grep -Ei 'scan|connect|auth|exploit' /var/log/auth.log /var/log/apache2/access.log | sort

Detect behavior drift of trusted users
awk '{print $1}' /var/log/auth.log | sort | uniq -c | awk '$1 > 20 {print "User with behavior spike:", $2}'

Trigger alert on unusual su use
grep 'session opened for user' /var/log/auth.log | grep -vE 'root|admin' | mail -s "SU Anomaly" you@example.com

Track sudo failure trends
grep 'sudo' /var/log/auth.log | grep -i 'incorrect' | awk '{print $1}' | sort | uniq -c

Monitor for new binaries run in /usr/local/bin
find /usr/local/bin -type f -exec stat -c '%n %y' {} + | sort -k2 | tail

Maintain visual dashboard of trust vs alerts
awk '{print $NF}' /var/log/fail2ban.log | sort | uniq -c > /tmp/trust_vs_alerts.txt && gnuplot trust_vs_alerts.txt

 Containment, Quarantine & Response

Kill container if network egress spikes
docker stats --no-stream | awk '$6+0 > 1000 {print $1}' | xargs -r docker kill

Quarantine suspected VM using vSwitch tag
virsh attach-interface guest suspicious-vm --type network --source quarantine --model virtio --config

Auto-delete malicious temp files
find /tmp /dev/shm -type f -exec sha256sum {} + | grep -Ff known_malware_hashes.txt | awk '{print $2}' | xargs -I{} rm -f {}

Transfer suspect logs to sandbox
scp /var/log/suspicious.log analyst@10.0.0.99:/mnt/sandbox/logs/

Push IDS alerts into incident queue
grep 'ALERT' /var/log/suricata/fast.log | tail -n 10 | curl -X POST -d @- http://incident.queue.local/api/new

Kill processes binding to unassigned ports
ss -tulnp | awk '$5 !~ /22|80|443/ {print $7}' | cut -d, -f2 | xargs -r kill -9

Lock outbound mail if spam detected
grep -i 'spam' /var/log/mail.log | awk '{print $6}' | sort | uniq -c | awk '$1 > 100 {print $2}' | xargs -I{} postconf -e "inet_interfaces = loopback-only"

Monitor /etc/hosts tampering
auditctl -w /etc/hosts -p wa -k hosts-watch

Snapshot containers daily
docker ps -q | xargs -I{} docker commit {} snapshot_{} && docker save snapshot_{} > /backups/$(date +%F)-{}.tar

Block beaconing to C2 IPs dynamically
grep 'C2 connection' /var/log/suricata/fast.log | awk '{print $9}' | xargs -I{} iptables -A OUTPUT -d {} -j REJECT 