

#include <sys/types.h>
#include <sys/param.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/time.h>
#ifndef WIN32
#include <sys/resource.h>
#endif
#include <time.h>
#include <limits.h>

#ifdef _MSC_VER
#include <intrin.h> /* __cpuid() */
#endif

#include "util.h"


/*
 * generic utils
 */

usec_t get_real_time(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((usec_t)tv.tv_sec) * USEC + tv.tv_usec;
}

usec_t get_user_time(int nthreads)
{
#ifdef WIN32
	return get_real_time();
#else
	usec_t cur;
	struct rusage u;
	int ncpu = get_number_of_cpus();
	if (getrusage(RUSAGE_SELF, &u) < 0)
		die("getrusage");
	cur = ((usec_t)u.ru_utime.tv_sec) * USEC + u.ru_utime.tv_usec;
	if (ncpu > nthreads) ncpu = nthreads;
	return cur / ncpu;
#endif
}

void die(const char *reason)
{
	fprintf(stderr, "%s\n", reason);
	exit(1);
}

void *zmalloc(unsigned len)
{
	void *p = malloc(len);
	if (!p)
		die("no mem");
	memset(p, 0, len);
	return p;
}

void bin2hex(const void *src, unsigned int srclen, char *dst, unsigned int dstlen)
{
	const uint8_t *s = src;
	static const char hextbl[] = "0123456789abcdef";
	if (dstlen < srclen*2 + 1)
		die("buffer overflow in bin2hex");
	for (; srclen > 0; s++, srclen--) {
		*dst++ = hextbl[*s >> 4];
		*dst++ = hextbl[*s & 15];
	}
	*dst = 0;
}

static int hexval(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	die("bad hex val");
	return -1;
}

unsigned int hex2bin(const char *src, void *dst, unsigned int dstlen)
{
	unsigned char *p = dst;

	if (strlen(src) / 2 > dstlen)
		die("buffer overflow in bin2hex");
	while (*src) {
		*p++ = (hexval(src[0]) << 4) | hexval(src[1]);
		src += 2;
	}
	return p - (unsigned char *)dst;
}

/*
 * Emulate pthreads on WIN32.
 */

#ifdef WIN32

struct _w32thread {
	void *(*fn)(void *);
	void *arg;
};

static DWORD WINAPI w32launcher(LPVOID arg)
{
	struct _w32thread *info = arg;
	info->fn(info->arg);
	free(info);
	return 0;
}

void pthread_create(pthread_t *t, pthread_attr_t *attr, void *(*fn)(void *), void *arg)
{
	struct _w32thread *info = zmalloc(sizeof(*info));
	info->fn = fn;
	info->arg = arg;
	*t = CreateThread(NULL, 0, w32launcher, info, 0, NULL);
	if (*t == NULL)
		die("CreateThread");
}

int pthread_join(pthread_t *t, void **ret)
{
	if (WaitForSingleObject(*t, INFINITE) != WAIT_OBJECT_0)
		die("WaitForSingleObject");
	CloseHandle(*t);
	return 0;
}

int pthread_mutex_init(pthread_mutex_t *lock, void *unused)
{
	*lock = CreateMutex(NULL, FALSE, NULL);
	if (*lock == NULL)
		die("CreateMutex");
	return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *lock)
{
	CloseHandle(*lock);
	return 0;
}

int pthread_mutex_lock(pthread_mutex_t *lock)
{
	if (WaitForSingleObject(*lock, INFINITE) != WAIT_OBJECT_0)
		die("WaitForSingleObject");
	return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *lock)
{
	if (!ReleaseMutex(*lock))
		die("ReleaseMutex");
	return 0;
}


void usleep(long usec)
{
	Sleep(usec / 1000);
}

#endif // WIN32

/*
 * CPU configuration
 */

int get_number_of_cpus(void)
{
	static int n = 0;
	if (n < 1) {
#ifdef WIN32
		SYSTEM_INFO si;
		GetSystemInfo(&si);
		n = si.dwNumberOfProcessors;
#else
#ifdef _SC_NPROCESSORS_ONLN
		n = sysconf(_SC_NPROCESSORS_ONLN);
#endif
#endif
	}
	if (n < 1) n = 1;
	return n;
}

/*
 * Is x86 CPU SSE2-capable?
 */

#if defined(__SSE2__)

static inline void cpuid(int dst[4], int op)
{
#if defined(_MSC_VER) || defined(__INTEL_COMPILER)
	__cpuid(dst, op);
#else
	asm("cpuid" : "=a"(dst[0]), "=b"(dst[1]), "=c"(dst[2]), "=d"(dst[3])
		    : "0"(op));
#endif
}

int cpu_has_sse2(void)
{
	static int got_sse2 = -1;
	int regs[4];
	if (got_sse2 < 0) {
		cpuid(regs, 1);
		got_sse2 = (regs[3] >> 26) & 1;
	}
	return got_sse2;
}

#else // !x86

int cpu_has_sse2(void) { return 0; }

#endif

