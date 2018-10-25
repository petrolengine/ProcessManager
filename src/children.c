#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/syslog.h>
#include <wait.h>

#include <common/pe_signal.h>

#include "children.h"
#include "utils.h"

#define FG_LISTENER_IPCHG 1

struct Child {
    char *mem;
    pid_t pid;
    uint32_t flag;
    const char *path;
    char *argv[11];
    struct Child *next;
};

struct {
    uint8_t count;
    uint8_t valide;
    struct Child *next;
} children, tmpChildren;

static inline void
tm_move()
{
    struct Child *c1 = children.next, *next = NULL;
    struct Child *c2 = NULL;

    while (c1) {
        next = c1->next;
        if (c1->pid != -1) {
            c2 = tmpChildren.next;
            while (c2) {
                if (strcmp(c1->path, c2->path) == 0) {
                    c2->pid = c1->pid;
                    tmpChildren.valide++;
                    break;
                }
                c2 = c2->next;
            }
            if (c2 == NULL && kill(c1->pid, SIGTERM) == -1) {
                syslog(LOG_EMERG, "kill %s error: %s",
                        c1->argv[0], strerror(errno));
            }
        }
        free(c1->mem);
        free(c1);
        c1 = next;
    }
    memcpy(&children, &tmpChildren, sizeof(tmpChildren));
    bzero(&tmpChildren, sizeof(tmpChildren));
}

static inline void
add_child(const char *data)
{
    char *pos = NULL, *p = NULL;
    struct Child *child = calloc(1, sizeof(struct Child));

    child->pid = -1;
    child->mem = strdup(data);

    // flag
    p = child->mem;
    pos = strchr(p, ' ');
    if (!pos || *(pos + 1) == '\0') { goto error; }
    *pos = '\0';
    child->flag = atoi(p);

    // path
    child->path = p = pos + 1;
    pos = strchr(p, ' ');
    if (pos) {
        *pos = '\0';
        p = pos + 1;
    }
    if (!is_valide_name(child->path)) { goto error; }

    // name
    child->argv[0] = strrchr(child->path, '/') + 1;

    // args
    for (int i = 1; i <= 9 && pos; i++) {
        child->argv[i] = p;
        pos = strchr(p, ' ');
        if (pos) {
            *pos = '\0';
            p = pos + 1;
        }
    }
    if (pos != NULL) { goto error; }

    child->next = tmpChildren.next;
    tmpChildren.next = child;
    tmpChildren.count ++;
    return ;
error:
    syslog(LOG_ERR, "add child '%s' failed",  data);
    free(child->mem);
    free(child);
}

bool
init_children()
{
#define CONFIG_FILE "/etc/linas/processmanager"
#define BUFFER_SIZE 1024
    FILE *fp = NULL;
    char buffer[BUFFER_SIZE] = { 0x00 };
    const char *data = NULL;

    if (access(CONFIG_FILE, R_OK) == -1) {
        goto error;
    }

    fp = fopen(CONFIG_FILE, "r");
    if (fp == NULL) {
        goto error;
    }
    
    bzero(&tmpChildren, sizeof(tmpChildren));
    while (fgets(buffer, BUFFER_SIZE, fp)) {
        data = strip(buffer);
        if (data == NULL) {
            continue;
        }
        if (data[0] == '#') {
            continue;
        }

        add_child(data);
    }
    tm_move();
    fclose(fp);
    printf("init children success, count: %d\n", children.count);
    return true;
error:
    syslog(LOG_ERR, "read '%s' error.", CONFIG_FILE);
    if (fp) {
        fclose(fp);
    }
    return false;
}

bool
reload_children(int *sigs, int sz)
{
    sigset_t bset;
    if (sigemptyset(&bset) == -1) {
        syslog(LOG_ERR, "sigemptyset error: %s", strerror(errno));
        return false;
    }
    for (int i = 0; i < sz; i++) {
        if (sigaddset(&bset, sigs[i]) == -1) {
            syslog(LOG_ERR, "sigaddset sig: %d,  error: %s",
                    sigs[i], strerror(errno));
            return false;
        }
    }
    if (sigprocmask(SIG_BLOCK, &bset, NULL) == -1) {
        syslog(LOG_ERR, "sigprocmask set block error: %s", strerror(errno));
        return false;
    }

    init_children();

    if (sigprocmask(SIG_UNBLOCK, &bset, NULL) == -1) {
        syslog(LOG_EMERG, "sigprocmask set unblock error: %s", strerror(errno));
        raise(SIGINT);
    }

    return true;
}

void
uninit_children()
{
    struct Child *child = children.next, *next = NULL;

    while (child) {
        next = child->next;

        free(child->mem);
        free(child);

        child = next;
    }
}

static inline void
start_process(struct Child *child)
{
    child->pid = fork();
    if (child->pid == 0) {
        if (execv(child->path, child->argv) == -1)
            syslog(LOG_ERR, "execv %s error: %s",
                    child->argv[0], strerror(errno));
        exit(EXIT_FAILURE);
    } else if (child->pid == -1) {
        syslog(LOG_EMERG, "fork error: %s", strerror(errno));
    }
}

void
check_and_start_all_children()
{
    struct Child *child = children.next;

    while (child) {
        if (child->pid == -1) {
            start_process(child);
        }
        child = child->next;
    }
}

void
stop_all_children()
{
    struct Child *child = children.next;

    while (child) {
        if (child->pid != -1) {
            if (kill(child->pid, SIGTERM) != -1) {
                if (waitpid(child->pid, NULL, 0) == -1) {
                    syslog(LOG_ERR, "waitpid %d process %s error. %s",
                            child->pid, child->argv[0], strerror(errno));
                } else {
                    syslog(LOG_INFO, "child %s terminated.", child->argv[0]);
                }
            } else {
                syslog(LOG_ERR, "kill %s error, pid %d. %s",
                        child->argv[0], child->pid, strerror(errno));
            }
        }
        child = child->next;
    }
}

void
broadcast_ip_changed()
{
    struct Child *child = children.next;

    while (child) {
        if (child->pid != -1 && (child->flag & FG_LISTENER_IPCHG)) {
            if (kill(child->pid, USIG_IPCHANGED) == -1) {
                syslog(LOG_ERR, "USIG_IPCHANGED error %s: %s",
                        child->argv[0], strerror(errno));
            }
        }
        child = child->next;
    }
}

void
on_child_terminated(pid_t pid)
{
    struct Child *child = children.next;

    while (child) {
        if (child->pid == pid) {
            child->pid = -1;
            syslog(LOG_INFO, "%s terminated", child->argv[0]);
            return;
        }
        child = child->next;
    }

    syslog(LOG_ALERT, "on_child_terminated can't process with pid %d", pid);
}
