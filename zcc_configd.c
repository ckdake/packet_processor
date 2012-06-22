#include <stdio.h>     /* standard I/O functions                         */
#include <unistd.h>    /* standard unix functions, like getpid()         */
#include <signal.h>    /* signal name macros, and the signal() prototype */

void catch_hup(int sig_num) {
    signal(SIGHUP, catch_hup);
    printf("Don't do that\n");
    fflush(stdout);
}

int main(int argc, char* argv[]) {

    signal(SIGHUP, catch_hup);

    for ( ;; )
        pause();
}
