#!/bin/bash

source $NTHOME/lib/function.ck
source $NTHOME/lib/blacklist.ck
  
check_crontab(){
    crontab -l > $NTHOME/lib/tempinfo/crontab-l.txt || true

    busybox cat /var/spool/cron/* > $NTHOME/lib/tempinfo/var_spool_cron.txt || true
    busybox cp -r /var/spool/cron/* $NTHOME/lib/tempinfo/ || true

    busybox cat /var/spool/cron/crontabs/* > $NTHOME/lib/tempinfo/var_spool_cron_crontabs.txt || true
    busybox cat /etc/crontab > $NTHOME/lib/tempinfo/etc_crontab.txt || true
    busybox cat /etc/cron.d/* > $NTHOME/lib/tempinfo/etc_cron.d.txt || true
    busybox find /etc -type f | busybox grep etc/cron | xargs cat > $NTHOME/lib/tempinfo/cron_other.txt || true
    touch $NTHOME/lib/tempinfo/croncheck
}

print_warn_message_simple "CHECK cron"
choose_and_call_function_without_parament check_crontab

if [ -f $NTHOME/lib/tempinfo/croncheck ]; then
    if [ -f $NTHOME/lib/tempinfo/crontab-l.txt ]; then
        check_cron_with_filename $NTHOME/lib/tempinfo/crontab-l.txt
        check_cron_with_filename $NTHOME/lib/tempinfo/var_spool_cron.txt 
        check_cron_with_filename $NTHOME/lib/tempinfo/var_spool_cron_crontabs.txt
        check_cron_with_filename $NTHOME/lib/tempinfo/etc_crontab.txt
        check_cron_with_filename $NTHOME/lib/tempinfo/etc_cron.d.txt
        check_cron_with_filename $NTHOME/lib/tempinfo/cron_other.txt
    fi
    busybox rm $NTHOME/lib/tempinfo/croncheck
fi


print_warn_message_simple "DO NOT FORGET: ONE CHECKING IS RM SOME CRONTAB FILES"
