#ifndef __TCP_WIN_H
#define __TCP_WIN_H

#define u8 unsigned char
#define u16 unsigned short
#define u32 unsigned int
#define u64 unsigned long long

#ifndef AF_INET
#define AF_INET		2
#endif

#ifndef AF_INET6
#define AF_INET6	10	/* IP version 6	*/
#endif 

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif


// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 ip;
    u8 direction; // 0-accept, 1-connect
    char task[TASK_COMM_LEN];
};

struct ipv6_data_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ts_us;
    u32 pid;
    u16 sport;
    u16 dport;
    u8 ip;
    u8 direction;
    char task[TASK_COMM_LEN];
};

#endif