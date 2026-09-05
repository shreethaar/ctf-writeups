/* time-lock (NNS CTF 2026) -- stand in front of libc's time().
 *
 * The binary gates on time(NULL) / 86400 == 0x2cbf34, i.e. the day index of
 * 1 January 9999. time() is a plain PLT import, so the dynamic loader resolves
 * it here first when this object is preloaded.
 *
 *   gcc -shared -fPIC -o faketime.so faketime.c
 *   LD_PRELOAD=./faketime.so ./time-lock
 */
#include <time.h>

time_t time(time_t *t)
{
    time_t v = 253370764800LL; /* 2932532 * 86400 == 9999-01-01 00:00:00 UTC */

    if (t)
        *t = v;
    return v;
}
