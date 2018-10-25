#pragma once

#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>

static inline bool
is_valide_name(const char *name)
{
    const char *pos = NULL;

    if (name[0] != '/') {
        return false;
    }

    if (access(name, X_OK) == -1) {
        syslog(LOG_ERR, "access '%s' error. %s", name, strerror(errno));
        return false;
    }
    pos = strrchr(name, '/');
    if (strcmp(pos, "processmanager") == 0) {
        syslog(LOG_ERR, "add 'processmanager' to processmanager");
        return false;
    }
    return true;
}

static inline const char *
strip(char *s)
{
    char *start = NULL, *p = NULL;

    while (*s && (isspace(*s) || !isprint(*s))) ++s;
    if (s != NULL) {
        char *fr = s + strlen(s) - 1;
        while ((isspace(*fr) || !isprint(*fr)) && fr >= s) --fr;
        *++fr = 0;
    }

    p = s;
    while (*p) {
        if (isspace(*p) || !isprint(*p)) {
            if (start == NULL) {
                start = p;
            }
        } else {
            if (start != NULL) {
                if (p - start >= 1) {
                    memmove(start + 1, p, strlen(p));
                    p = start + 1;
                }
                start = NULL;
            }
        }
        p++;
    }

    return s;
}
