#include "signal.h"
#include <signal.h>
#include <stdlib.h>


struct my_signal {
    const char *name;
    int signal;
};

static struct my_signal sigstrnum[] =
{
    { "HUP",    SIGHUP },
    { "INT",    SIGINT },
    { "QUIT",   SIGQUIT },
    { "ILL",    SIGILL },
    { "TRAP",   SIGTRAP },
    { "ABRT",   SIGABRT },
    { "IOT",    SIGIOT },
    { "BUS",    SIGBUS },
    { "FPE",    SIGFPE },
    { "KILL",   SIGKILL },
    { "USR1",   SIGUSR1 },
    { "SEGV",   SIGSEGV },
    { "USR2",   SIGUSR2 },
    { "PIPE",   SIGPIPE },
    { "ALRM",   SIGALRM },
    { "TERM",   SIGTERM },
    { "CHLD",   SIGCHLD },
    { "CONT",   SIGCONT },
    { "STOP",   SIGSTOP },
    { "TSTP",   SIGTSTP },
    { "TTIN",   SIGTTIN },
    { "TTOU",   SIGTTOU },
    { "URG",    SIGURG },
    { "XCPU",   SIGXCPU },
    { "XFSZ",   SIGXFSZ },
    { "VTALRM", SIGVTALRM },
    { "PROF",   SIGPROF },
    { "WINCH",  SIGWINCH },
    { "IO",     SIGIO },
    { "SYS",    SIGSYS },

    #ifdef SIGPOLL
    { "POLL", SIGPOLL },
    #endif

    #ifdef SIGPWR
    { "PWR", SIGPWR },
    #endif

    #ifdef SIGEMT
    { "EMT", SIGEMT },
    #endif

    #ifdef SIGINFO
    { "INFO", SIGINFO },
    #endif

    #ifdef SIGSTKFLT
    { "STKFLT", SIGSTKFLT },
    #endif

    #ifdef SIGCLD
    { "CLD", SIGCLD },
    #endif

    #ifdef SIGLOST
    { "LOST", SIGLOST },
    #endif

    #ifdef SIGCANCEL
    { "CANCEL", SIGCANCEL },
    #endif

    #ifdef SIGTHAW
    { "THAW", SIGTHAW },
    #endif

    #ifdef SIGFREEZE
    { "FREEZE", SIGFREEZE },
    #endif

    #ifdef SIGLWP
    { "LWP", SIGLWP },
    #endif

    #ifdef SIGWAITING
    { "WAITING", SIGWAITING },
    #endif

    { NULL, -1 }
};

const char *sig_to_str(int s) {
    int i;

    for (i = 0; sigstrnum[i].name; i++)
        if (sigstrnum[i].signal == s)
            return sigstrnum[i].name;
    return "SIGUNKNOWN";
}