/*
 *   This file is part of untrace.
 *
 *   untrace is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   untrace is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with untrace.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <elfutils/libdwfl.h>
#include <sys/user.h>
#include <signal.h>
#include <getopt.h>
#include <termios.h>
#include <libunwind.h>
#include <libunwind-x86_64.h>
#include <libunwind-ptrace.h>
#include <strsig.h>

static const unsigned PTRACE_OPTIONS = PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK
                                     | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC
                                     | PTRACE_O_TRACEEXIT;

void die(char *s) {
    perror(s);
    exit(1);
}

void warn(char *s) {
    fprintf(stderr, "untrace: %s\n", s);
}

ssize_t get_comm(pid_t pid, char **s) {
    char path[4096];
    int rv = snprintf(path, 4096, "/proc/%u/comm", pid);
    if (rv > 4096) {
        *s = NULL;
        return -1;
    } else {
        FILE *f = fopen(path, "r");
        size_t n = 0;
        ssize_t srv = getline(s, &n, f);
        fclose(f);
        if (*s != NULL) {
            (*s)[srv-1] = '\0';
        }
        return srv;
    }
}

int print_backtrace(FILE *fp, unw_addr_space_t as, pid_t pid) {
    struct UPT_info *ui = _UPT_create(pid);
    if (!ui) {
        perror("_UPT_create");
        return -1;
    }
    unw_cursor_t c;
    int rv = unw_init_remote(&c, as, ui);
    if (rv != 0) {
        perror("unw_init_remote");
        return -1;
    }
    Dwfl_Callbacks dwfl_callbacks;
    dwfl_callbacks.find_elf = dwfl_linux_proc_find_elf;
    dwfl_callbacks.find_debuginfo = dwfl_standard_find_debuginfo;
    dwfl_callbacks.debuginfo_path = NULL;
    Dwfl *dwfl_session = dwfl_begin(&dwfl_callbacks);
    rv = dwfl_linux_proc_report(dwfl_session, pid);
    if (rv != 0) {
        perror("dwfl_linux_proc_report");
        return -1;
    }
    rv = dwfl_report_end(dwfl_session, NULL, NULL);
    if (rv != 0) {
        perror("dwfl_report_end");
        return -1;
    }
    do {
        unw_word_t ip;
        unw_get_reg(&c, UNW_REG_IP, &ip);
        Dwfl_Module *module = dwfl_addrmodule(dwfl_session, ip);
        const char *funcname = dwfl_module_addrname(module, ip);
        Dwfl_Line *line = dwfl_getsrc(dwfl_session, ip);
        if (line != NULL) {
            int nline;
            const char *filename = dwfl_lineinfo(line, &ip, &nline, NULL, NULL, NULL);
            fprintf(fp, "  > %s (%s:%d)\n", funcname, filename, nline);
        } else {
            fprintf(fp, "  > %s [%p]\n", funcname, ip);
        }
    } while (unw_step(&c) > 0);
    _UPT_destroy(ui);
    return 0;
}

int main(int argc, char **argv) {
    int rv;
    long lrv;
    unw_addr_space_t as = unw_create_addr_space(&_UPT_accessors, 0);
    if (!as) {
        die("unw_create_addr_space");
    }

    int save_term = 0;

    static char *optstring = "+t";
    static struct option longopts[] = {
        { "save-term", no_argument, NULL, 't' },
        { NULL, 0, NULL, 0 }
    };
    int opt = getopt_long(argc, argv, optstring, longopts, NULL);
    while (opt != -1) {
        switch (opt) {
            case 't':
                fprintf(stderr, "got save term\n");
                save_term = 1;
                break;
        }
        opt = getopt_long(argc, argv, optstring, longopts, NULL);
    }

    if (optind >= argc) {
        fprintf(stderr, "usage: untrace [-t|--save-term] <executable> [args...]\n");
        exit(EXIT_FAILURE);
    }
    argv += optind;

    fprintf(stderr, "%s\n", argv[0]);

    int ttyfd;
    struct termios termattrs;
    if (save_term) {
        ttyfd = -1;
        if (isatty(STDIN_FILENO)) {
            ttyfd = STDIN_FILENO;
        } else if (isatty(STDOUT_FILENO)) {
            ttyfd = STDOUT_FILENO;
        } else if (isatty(STDERR_FILENO)) {
            ttyfd = STDERR_FILENO;
        }
        if (ttyfd != -1) {
            rv = tcgetattr(ttyfd, &termattrs);
            if (rv != 0) {
                die("failed to get terminal attributes");
            }
        } else {
            warn("--save-term was requested but not connected to a tty\n");
            save_term = 0;
        }
    }

    pid_t cpid = fork();
    if (cpid == 0) {
        lrv = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (lrv == -1) {
            die("failed to request tracing in child");
        } else {
            execvp(*argv, argv);
            die("failed to execvp in child");
        }
    } else if (cpid > 0) {
        int wstatus;
        pid_t wpid = waitpid(cpid, &wstatus, __WALL);
        if (WIFSTOPPED(wstatus)) {
            lrv = ptrace(PTRACE_SETOPTIONS, wpid, NULL, PTRACE_OPTIONS);
            if (lrv == -1) {
                die("5");
            }
            lrv = ptrace(PTRACE_CONT, wpid, NULL, 0);
            if (lrv == -1) {
                die("7");
            }
            int running = 1;
            wpid = waitpid(-1, &wstatus, __WALL);
            while (wpid != -1) {
                if (WIFSTOPPED(wstatus)) {
                    if ((wstatus>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) ||
                            (wstatus>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))) ||
                            (wstatus>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8)))) {
                        if (save_term) {
                            warn("it appears the process has spawned another process;  restoring terminal attributes will be unavailable");
                            save_term = 0;
                        }
                        lrv = ptrace(PTRACE_CONT, wpid, NULL, 0);
                        if (lrv == -1) {
                            die("failed to restart tracee after EVENT_{CLONE,*FORK}");
                        }
                    } else if (wstatus>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8))) {
                        lrv = ptrace(PTRACE_CONT, wpid, NULL, 0);
                        if (lrv == -1) {
                            die("failed to restart tracee after EVENT_EXEC");
                        }
                    } else if (wstatus>>8 == (SIGTRAP | (PTRACE_EVENT_EXIT<<8))) {
                        char *comm = NULL;
                        get_comm(wpid, &comm);
                        long pstatus;
                        lrv = ptrace(PTRACE_GETEVENTMSG, wpid, NULL, &pstatus);
                        if (save_term) {
                            rv = tcsetattr(ttyfd, TCSANOW, &termattrs);
                            if (rv != 0) {
                                warn("failed to restore terminal attributes");
                            }
                        }
                        if (lrv == -1) {
                            fprintf(stderr, "--> pid %ld (%s) terminating, reason: unknown\n", wpid, comm);
                        } else {
                            if (WIFEXITED(pstatus)) {
                                fprintf(stderr, "--- pid %ld (%s) terminating, reason: exited with %d\n", wpid, comm, WEXITSTATUS(pstatus));
                            } else if (WIFSIGNALED(pstatus)) {
                                const char *signame = strsig(WTERMSIG(pstatus));
                                if (signame) {
                                    fprintf(stderr, "--- pid %ld (%s) terminating, reason: received signal %s\n", wpid, comm, signame);
                                } else {
                                    fprintf(stderr, "--- pid %ld (%s) terminating, reason: received unknown signal (%d)\n", wpid, comm, WTERMSIG(pstatus));
                                }
                            }
                            fprintf(stderr, "  Stacktrace:\n");
                            rv = print_backtrace(stderr, as, wpid);
                            if (rv == -1) {
                                // TODO: not sure wtf2do
                            }
                        }
                        if (comm != NULL) {
                            free(comm);
                        }
                        lrv = ptrace(PTRACE_CONT, wpid, NULL, 0);
                        if (lrv == -1) {
                            die("failed to restart tracee after EVENT_EXIT");
                        }
                    } else if (WSTOPSIG(wstatus) == SIGSTOP) {
                        lrv = ptrace(PTRACE_CONT, wpid, NULL, 0);
                        if (lrv == -1) {
                            die("failed to start cloned process");
                        }
                    } else {
                        lrv = ptrace(PTRACE_CONT, wpid, NULL, WSTOPSIG(wstatus));
                        if (lrv == -1) {
                            die("failed to forward signal to tracee");
                        }
                    }
                }
                wpid = waitpid(-1, &wstatus, __WALL);
            }
        } else {
            die("unexpected waitpid result");
        }
    } else {
        die("fork");
    }
}
