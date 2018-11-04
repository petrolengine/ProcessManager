#include <sys/syslog.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <wait.h>
#include <string.h>

#include <common/pe_signal.h>

#include "children.h"

static volatile bool eXit = false;
static volatile bool rEload = false;

static void
handler_chld()
{
    pid_t pid = 0;

    if (eXit) return;

    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
        on_child_terminated(pid);
    errno = 0;
}

static void
safe_exit()
{
    stop_all_children();
    uninit_children();
    closelog();
    exit(0);
}

static void
signal_handler(int sig) {
    switch (sig) {
    case SIGTERM:
        eXit = true;
        break;
    case SIGCHLD:
        handler_chld();
        break;
    case SIGINT:
        safe_exit();
        break;
    case SIGUSR1:
        rEload = true;
        break;
    case USIG_IPCHANGED:
        if (eXit)
            return;
        broadcast_ip_changed();
        break;
    }
}

static void
Signal(int sig)
{
    if (signal(sig, signal_handler) == SIG_ERR) {
        syslog(LOG_ERR, "signal error sig: %d, err: %s", sig, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

int main()
{
    int sigs[] = {
        SIGTERM, SIGINT, SIGCHLD, SIGUSR1, USIG_IPCHANGED
    };
#define SIGS_SIZE sizeof(sigs) / sizeof(*sigs)

    openlog("processmanager", LOG_PID, LOG_LOCAL0);

    if (!init_children())
        return -1;

//    if (daemon(0, 0) == -1) {
//        syslog(LOG_ERR, "daemon error: %s", strerror(errno));
//        return -1;
//    }

    for (unsigned int i = 0; i < SIGS_SIZE; i++) {
        Signal(sigs[i]);
    }

    while (!eXit) {
        if (rEload && !reload_children(sigs, SIGS_SIZE)) {
            sleep(1);
        } else {
            rEload = false;
            check_and_start_all_children();
            pause();
        }
    }
    safe_exit();
    return 0;
}
