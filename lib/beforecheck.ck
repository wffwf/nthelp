#!/bin/bash
source $NTHOME/lib/function.ck

backup(){
    busybox cp ~/.bash_history $NTHOME/lib/tempinfo/bash_history.txt
    print_info_message_simple "~/.bash_history back to bash_history.txt!"
}
cmds(){
    dpkg -V > $NTHOME/lib/tempinfo/dpkg-V.txt
    print_info_message_simple "dpkg -V result save in dpkg-V.txt!"
    busybox cat $NTHOME/lib/tempinfo/dpkg-V.txt

    busybox env > $NTHOME/lib/tempinfo/env.txt
    print_info_message_simple "busybox env result save in env.txt!"
    busybox cat $NTHOME/lib/tempinfo/env.txt

    busybox find /var/www/html -name robots.txt | xargs strings -f
    busybox find /var/www/html -name robots.txt -exec mv {} $NTHOME/lib/tempinfo/ \;
    print_info_message_simple "/var/www/html/robots.txt save to tempinfo!"

    busybox find /var/www/html \( -name '*.tar.gz' -o -name '*.zip' -o -name '*.rar' -type d -o -name '.git' -type d -o -name '.DS_store' \) 
    busybox find /var/www/html \( -name '*.tar.gz' -o -name '*.zip' -o -name '*.rar' -type d -o -name '.git' -type d -o -name '.DS_store' \)  -exec mv {} $NTHOME/lib/tempinfo/ \;
    print_info_message_simple "/var/www/html/www.[zip|rar|tar|tar.gz] save to tempinfo!"
    
}
mustdone(){
    (busybox which perl || true ) && (busybox which g++ || true ) && (busybox which gcc || true) && (busybox which python | busybox xargs ls -al || true) && (busybox which python2 | busybox xargs ls -al || true) && (busybox which python3 | busybox xargs ls -al || true) &&  (python -V || ture) && ( python2 -V || ture) && (python3 -V || true) && echo "IF gcc/g++, try [chkrootkit] or [rkhunter --check --sk]" && echo "IF python, try [python GScan.py --sug]" && echo "IF perl, try [logwatch.pl]"
    echo
}
backup
cmds
print_warn_message_simple "SOME TOOLS!"
choose_and_call_function_without_parament mustdone
