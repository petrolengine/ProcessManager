#pragma once

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#define FG_LISTEN_IPCHG 0x00000002

bool init_children();
void uninit_children();

bool reload_children(int *sigs, int sz);
void check_and_start_all_children();
void stop_all_children();

void on_child_terminated(pid_t pid);

void broadcast_ip_changed();
