#!/bin/bash
if [ -z "$NTHOME" ]; then  
  echo "Error: NTHOME is not set."  
  echo "Try: source .src"
  exit 1  
fi  
bash ./lib/beforecheck.ck
bash ./lib/osinfo.ck
bash ./lib/alias.ck
bash ./lib/export.ck
bash ./lib/simple_cat.ck /etc/passwd
bash ./lib/simple_cat.ck /etc/shadow
bash ./lib/privilege_etc_passwd.ck
bash ./lib/simple_cat.ck ~/.bashrc
bash ./lib/simple_cat.ck ~/.bash_profile
bash ./lib/simple_cat.ck ~/.bash_login
bash ./lib/ps.ck
bash ./lib/netstat.ck
bash ./lib/cron.ck
bash ./lib/rc.ck
bash ./lib/cmdstat.ck
bash ./lib/privilege_exe_cmd.ck
bash ./lib/ssh_key.ck
