#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xenctrl.h>
#include <xenstore.h>

static struct option varstored_watch_option[] = {
    {"domid", 1, NULL, 'd'},
    {"uuid", 1, NULL, 'u'},
    {NULL, 0, NULL, 0}
};

static pid_t
start_varstored(char *domid_str, char *uuid)
{
    const char *path = "/usr/sbin/varstored";
    pid_t pid;
    char *process_name = NULL;
    char *vpid = NULL;
    char *uuid_param = NULL;
    domid_t domid;
    int ret;

    domid = (domid_t) strtol(domid_str, NULL, 0);

    ret = asprintf(&process_name, "varstored-%d", domid);
    if (ret == -1) {
        syslog(LOG_ERR, "asprintf process_name failed: %d, %s", errno,
               strerror(errno));
        return -1;
    }
    ret = asprintf(&vpid, "/var/run/varstored-pid-%d", domid);
    if (ret == -1) {
        syslog(LOG_ERR, "asprintf pidfile failed: %d, %s", errno,
               strerror(errno));
        return -1;
    }
    ret = asprintf(&uuid_param, "uuid:%s", uuid);
    if (ret == -1) {
        syslog(LOG_ERR, "asprintf uuid failed: %d, %s", errno, strerror(errno));
        return -1;
    }

    pid = fork();
    if (pid == -1) {
        syslog(LOG_ERR, "Failed to fork varstored");
    } else if (pid == 0) {
        execl(path, process_name,
                    "--depriv",
                    "--domain", domid_str,
                    "--backend", "oxtdb",
                    "--pidfile", vpid,
                    "--arg", uuid_param,
                    "--gid", "415",
                    "--uid", "416",
                    NULL);
    }
    // Free the strings.
    free(process_name);
    free(vpid);
    free(uuid_param);

    return pid;
}

#define XS_VARSTORED_WATCH_PID_PATH "/local/domain/%s/varstored-watch-pid"

static bool
xs_write_pid(struct xs_handle *xsh, char * domid)
{
    char *varstore_watch_pid = NULL;
    char *key = NULL;
    bool ret = false;

    /* write out the pid so libxl can tear us down on guest shutdown */
    if (asprintf(&varstore_watch_pid, "%u", getpid()) != -1)
        if (asprintf(&key, XS_VARSTORED_WATCH_PID_PATH, domid) != -1)
            ret = xs_write(xsh, 0, key, varstore_watch_pid, strlen(varstore_watch_pid));

    free(key);
    free(varstore_watch_pid);
    return ret;
}

static void
usage(const char *prog)
{
    int i;

    fprintf(stderr, "Usage: %s <options>\n\n", prog);

    for (i = 0; i < 2; i++) {
        if (varstored_watch_option[i].has_arg) {
            fprintf(stderr, "\t--%s <val>\n",
                    varstored_watch_option[i].name);
        } else {
            fprintf(stderr, "\t--%s\n", varstored_watch_option[i].name);
        }
    }

    fprintf(stderr, "\n");
}

int
main(int argc, char **argv)
{
    int rc;
    struct xs_handle *xsh = NULL;
    char *domid_str = NULL;
    char *uuid = NULL;
    const char *prog;
    pid_t varstored_pid;

    prog = basename(argv[0]);

    while (1) {
        char c;

        c = getopt_long(argc, argv, "", varstored_watch_option, NULL);
        if (c == -1)
            break;

        switch (c) {
           case 'd':
                domid_str = strdup(optarg);
                break;
            case 'u':
                uuid = strdup(optarg);
                break;
            default:
                usage(prog);
                exit(2);
        }
    }

    if (domid_str == NULL || uuid == NULL) {
        usage(prog);
        exit(2);
    }

    xsh = xs_open(0);
    if (!xsh) {
        syslog(LOG_ERR, "Couldn't open xenstore: %d, %s", errno, strerror(errno));
        return -1;
    }

    if (!xs_write_pid(xsh, domid_str)) {
        syslog(LOG_ERR, "Failed to write pid to xenstore: %d, %s\n", errno, strerror(errno));
        xs_close(xsh);
        return -1;
    }

    xs_close(xsh);

    //Start varstored for the first time.
    varstored_pid = start_varstored(domid_str, uuid);
    if (varstored_pid == -1) {
        syslog(LOG_ERR, "Failed to fork varstored\n");
        return -1;
    }

    //Start loop for restarting varstored if it goes down.
    while (true) {
        waitpid(varstored_pid, &rc, 0);
        if (WIFEXITED(rc)) {
            syslog(LOG_ERR, "Varstored failed to start normally and exited...not retrying. Exit status %d\n", WEXITSTATUS(rc));
            break;
        } else if (WIFSIGNALED(rc)) {
            syslog(LOG_ERR, "Varstored killed by signal %d, restarting.\n", WTERMSIG(rc));
            varstored_pid = start_varstored(domid_str, uuid);
        }
    }

    return 0;
}
