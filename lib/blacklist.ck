#!/bin/bash
source $NTHOME/lib/function.ck
# only bash can use 'shopt'
if ! command -v shopt &> /dev/null; then  
    echo "This script requires bash shell." >&2  
    echo "Grep 'shopt' in lib/function.ck , Modify it for force RUN" >&2  
    exit 1  
fi  
blackpslist=("ftp" "redis" "rsync" "apache" "mysql" "python")  

