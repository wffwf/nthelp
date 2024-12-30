#!/bin/bash

print_warn_message_simple() {  
    local message="$1"  
    local border_width=80
    local content_width=40    
    printf "%*s\n" $border_width "" | tr ' ' '*'  
    printf "%*sWARN: %-*s\n" $((border_width/2-6)) "" $content_width "$message"  
    printf "%*s\n" $border_width "" | tr ' ' '*'  
}  

print_info_message_simple() {
    local message="$1"
    local border_width=80
    local content_width=40
    printf "%*s\n" $border_width "" | tr ' ' '*'
    printf "%*sINFO: %-*s\n" $((border_width/2-6)) "" $content_width "$message"
    printf "%*s\n" $border_width "" | tr ' ' '*'
}


choose_and_call_function_without_parament(){
    read -r -p "Press any key to Continue, YES or No? [Y/n] " input

    case $input in
        [nN][oO]|[nN])
            ;;
        *)
            $1
            ;;
    esac

}

choose_and_call_function_with_one_parament(){
    read -r -p "Press any key to Continue, YES or No? [Y/n] " input

    case $input in
        [nN][oO]|[nN])
            ;;
        *)
            $1 $2
            ;;
    esac

}

check_by_cat() {
    busybox cat $1
    print_info_message_simple "FINISH CHECK "$1
    echo 
}

check_black_ps_list_with_filename(){
    print_warn_message_simple "CHECK weakable process"
    read -r -p "Press any key to Continue, YES or No? [Y/n] " input

    case $input in
        [nN][oO]|[nN])
            ;;

        *)
            shopt -s nocasematch
            while IFS= read -r line; do
                for keyword in "${blackpslist[@]}"; do
                  if [[ "$line" == *"$keyword"* ]]; then
                      echo "ERROR: weak process found: $line"
                      break
                  fi
                done
            done < $1
            shopt -u nocasematch
            ;;
    esac
}

check_cron_with_filename(){
    print_warn_message_simple "AUTO CHECK "$1
    busybox cat $1
    read -r -p "AUTO FIND cron CMD? Press any key to Continue, YES or No? [Y/n] " input

    case $input in
        [nN][oO]|[nN])
            ;;

        *)
            shopt -s nocasematch
            while IFS= read -r line; do
                if [[ "$line" =~ ^([0-9*]+) ]]; then  
                    echo "Crontab task found: $line"    
                fi  
            done < $1
            shopt -u nocasematch
            ;;
    esac
}


check_inputfile_byloop(){  
    while true; do  
        echo -n "Which file do you want to CHECK? type N to exit:  "  
        read filename  
      
        if [ "$filename" = "N" ] || [ "$filename" = "n" ]; then  
            break  
        fi  
      
        if [ -f "$filename" ]; then  
            busybox cat "$filename"  
        else  
            echo "ERROR: Unknow filename"  
        fi  
      
    done
}
