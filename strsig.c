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

#include <signal.h>
#include <stddef.h>
#include <strsig.h>

struct {
    int signo;
    const char *name;
} sigtbl[] = {
#ifdef SIGINT
    { SIGINT, "SIGINT" },
#endif
#ifdef SIGILL
    { SIGILL, "SIGILL" },
#endif
#ifdef SIGABRT
    { SIGABRT, "SIGABRT" },
#endif
#ifdef SIGFPE
    { SIGFPE, "SIGFPE" },
#endif
#ifdef SIGSEGV
    { SIGSEGV, "SIGSEGV" },
#endif
#ifdef SIGTERM
    { SIGTERM, "SIGTERM" },
#endif
#ifdef SIGHUP
    { SIGHUP, "SIGHUP" },
#endif
#ifdef SIGQUIT
    { SIGQUIT, "SIGQUIT" },
#endif
#ifdef SIGTRAP
    { SIGTRAP, "SIGTRAP" },
#endif
#ifdef SIGIOT
    { SIGIOT, "SIGIOT" },
#endif
#ifdef SIGEMT
    { SIGEMT, "SIGEMT" },
#endif
#ifdef SIGKILL
    { SIGKILL, "SIGKILL" },
#endif
#ifdef SIGBUS
    { SIGBUS, "SIGBUS" },
#endif
#ifdef SIGSYS
    { SIGSYS, "SIGSYS" },
#endif
#ifdef SIGPIPE
    { SIGPIPE, "SIGPIPE" },
#endif
#ifdef SIGALRM
    { SIGALRM, "SIGALRM" },
#endif
#ifdef SIGUSR1
    { SIGUSR1, "SIGUSR1" },
#endif
#ifdef SIGUSR2
    { SIGUSR2, "SIGUSR2" },
#endif
#ifdef SIGCHLD
    { SIGCHLD, "SIGCHLD" },
#endif
#ifdef SIGCLD
    { SIGCLD, "SIGCLD" },
#endif
#ifdef SIGPWR
    { SIGPWR, "SIGPWR" },
#endif
#ifdef SIGWINCH
    { SIGWINCH, "SIGWINCH" },
#endif
#ifdef SIGURG
    { SIGURG, "SIGURG" },
#endif
#ifdef SIGPOLL
    { SIGPOLL, "SIGPOLL" },
#endif
#ifdef SIGIO
    { SIGIO, "SIGIO" },
#endif
#ifdef SIGSTOP
    { SIGSTOP, "SIGSTOP" },
#endif
#ifdef SIGTSTP
    { SIGTSTP, "SIGTSTP" },
#endif
#ifdef SIGCONT
    { SIGCONT, "SIGCONT" },
#endif
#ifdef SIGTTIN
    { SIGTTIN, "SIGTTIN" },
#endif
#ifdef SIGTTOU
    { SIGTTOU, "SIGTTOU" },
#endif
#ifdef SIGVTALRM
    { SIGVTALRM, "SIGVTALRM" },
#endif
#ifdef SIGPROF
    { SIGPROF, "SIGPROF" },
#endif
#ifdef SIGXCPU
    { SIGXCPU, "SIGXCPU" },
#endif
#ifdef SIGXFSZ
    { SIGXFSZ, "SIGXFSZ" },
#endif
#ifdef SIGWAITING
    { SIGWAITING, "SIGWAITING" },
#endif
#ifdef SIGLWP
    { SIGLWP, "SIGLWP" },
#endif
#ifdef SIGFREEZE
    { SIGFREEZE, "SIGFREEZE" },
#endif
#ifdef SIGTHAW
    { SIGTHAW, "SIGTHAW" },
#endif
#ifdef SIGCANCEL
    { SIGCANCEL, "SIGCANCEL" },
#endif
#ifdef SIGLOST
    { SIGLOST, "SIGLOST" },
#endif
    { 0, NULL }
};

const char *strsig(int signo) {
    int i = 0;
    while(sigtbl[i].name != NULL && sigtbl[i].signo != signo) {
        i++;
    }
    if (sigtbl[i].name == NULL) {
    }
    return sigtbl[i].name;
}
