#!/bin/bash

source $NTHOME/lib/function.ck
source $NTHOME/lib/blacklist.ck

print_warn_message_simple "CHECK cmd files in Linux PATH"

# 判断是否传入了参数，如果没有传入参数，默认设置为30天
if [ $# -eq 0 ]; then
    num_days=30
else
    num_days=$1
fi

print_info_message_simple "CHECK cmd files Changes in ${num_days}(SETable) day ago"

# 根据传入的天数参数，计算对应的时间戳（以秒为单位）
ago_timestamp=$(date +%s --date="${num_days} day ago")

# 先获取$PATH环境变量中以冒号分隔的各个路径，并换行输出
busybox echo $PATH | busybox tr ':' '\n' | while read path; do
    # 判断路径是否存在，如果不存在则跳过本次循环
    if [! -d "$path" ]; then
        continue
    fi
    # 遍历该路径下的所有文件
    for file in "$path"/*; do
        # 判断是否是普通文件，如果是则进行后续检查
        if [ -f "$file" ] ; then
            # 获取文件的修改时间戳（以秒为单位）
            file_modify_timestamp=$(busybox stat -c %Z "$file")
            # 判断文件修改时间戳是否大于指定时间戳，如果大于则表示在相应天数内有修改，进行输出
            if [ "$file_modify_timestamp" -gt "$ago_timestamp" ]; then
                busybox echo -n "$file " && busybox stat $file | busybox grep Change
            fi
        fi
    done
done
# 根据BAK关键字检查是否存在备份文件，一般为题目故意提供
print_info_message_simple "FIND BAK files in Linux PATH simply"

find_bak_files(){
    busybox echo $PATH | busybox tr ':' '\n' | busybox xargs -I {} busybox find {} -iname "*bak*"
    echo
}

choose_and_call_function_without_parament find_bak_files

