#!/bin/bash

# Basic system info checker before privilege escalation
#system info (kernel version, distribution, hostname,...)
#hostname, uname -a, /proc/version
print_sysinfo(){
    kernel_=$(cat /proc/version | awk '{print $3}')
    hostname_=$(hostname)
    distribution_=$(cat /etc/issue | cut -d " " -f 1-2)
    
    echo "SYSTEM INFORMATION"
    echo -e "hostname: ${hostname_}\
    \nkernel version: ${kernel_}\
    \ndistribution: ${distribution_}"
}

#cpu
print_cpuinfo(){
    model=$(lscpu | grep "Model name")
    architecture=$(lscpu | grep "Architecture")
    thread=$(lscpu | grep "Thread(s) per core")

    echo "CPU INFO"
    echo -e "${model}\
    \n${architecture}\
    \n${thread}
    "
}

#ram, disk,
print_diskinfo(){
    disk=$(df -h)
    ram=$(free -h)

    echo "DISK INFO"
    echo -e "disk usage: \n${disk}\n\
    \nram usage: \n${ram}
    "
}

#net info
#ip, mac, tcp connection
print_netinfo(){
    ip_address=$(ip a | grep "inet" | cut -d " " -f 6-)
    mac_address=$(ip a | grep "ether" | cut -d " " -f 6)
    open_connection=$(ss -tl4 | grep "LISTEN" | awk '{print $4}')
    num_connection=$(ss -tl4 | grep "LISTEN" | wc -l)

    echo "NETWORK INFORMATION"
    echo -e "Ip addresses:\n${ip_address}\n\
    \nMAC addresses: \n${mac_address}\n\
    \nOpen connection: ${num_connection}\n\
    \nConnections: \n${open_connection}
    "
}

print_all()
{
    print_sysinfo
    echo ""
    print_netinfo
    echo ""
    print_cpuinfo
    echo ""
    print_diskinfo    
}

print_all
