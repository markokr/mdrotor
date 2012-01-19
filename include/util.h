#define _GNU_SOURCE 1

#include <sys/types.h>
#include <sys/param.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <pthread.h>
#endif

#ifdef inline
#warning inline defined
#endif
#if 1
#define inline inline __attribute__((always_inline))
#endif

/* check endianess */
#if !defined(BYTE_ORDER) || (BYTE_ORDER != LITTLE_ENDIAN && BYTE_ORDER != BIG_ENDIAN)
#error Define BYTE_ORDER to be equal to either LITTLE_ENDIAN or BIG_ENDIAN
#endif
#if BYTE_ORDER == BIG_ENDIAN
#define WORDS_BIGENDIAN
#endif

/* give offset of a field inside struct */
#ifndef offsetof
#define offsetof(type, field) ((unsigned long)&(((type *)0)->field))
#endif

/* given pointer to field inside struct, return pointer to struct */
#ifndef container_of
#define container_of(ptr, type, field) ((type *)((char *)(ptr) - offsetof(type, field)))
#endif

/* rotate uint32 */
#define ror32(v, s) rol32(v, 32 - (s))
static inline uint32_t rol32(uint32_t v, int s)
{
	return (v << s) | (v >> (32 - s));
}

/* rotate uint64 */
#define ror64(v, s) rol64(v, 64 - (s))
static inline uint64_t rol64(uint64_t v, int s)
{
	return (v << s) | (v >> (64 - s));
}

/* hton64 */
#define ntoh64(x) hton64(x)
static inline uint64_t hton64(uint64_t v) {
#ifndef WORDS_BIGENDIAN
	return htonl(v >> 32) | ((uint64_t)htonl(v) << 32);
#else
	return v;
#endif
};

static inline void cpu2be_many32(uint32_t *w, int cnt)
{
	for (; cnt > 0; w++, cnt--)
		*w = ntohl(*w);
}

static inline void cpu2be_many64(uint64_t *w, int cnt)
{
	for (; cnt > 0; w++, cnt--)
		*w = ntoh64(*w);
}
#define be2cpu_many32(w, c) cpu2be_many32(w, c)
#define be2cpu_many64(w, c) cpu2be_many64(w, c)

/* time lookup */
#define USEC 1000000
typedef uint64_t usec_t;
usec_t get_real_time(void);
usec_t get_user_time(int nthreads);

/* random utilities */
void die(const char *reason);
void *zmalloc(unsigned len);
void bin2hex(const void *src, unsigned int srclen, char *dst, unsigned int dstlen);
unsigned int  hex2bin(const char *src, void *dst, unsigned int dstlen);

/* cpu info */
int get_number_of_cpus(void);
int cpu_has_sse2(void);

/*
 * win32 compat functions - pthreads, usleep
 */

#ifdef WIN32

#define pthread_t HANDLE
#define pthread_mutex_t HANDLE
#define pthread_attr_t int

#define pthread_create		u_pthread_create
#define pthread_mutex_init	u_pthread_mutex_init
#define pthread_mutex_destroy	u_pthread_mutex_destroy
#define pthread_mutex_lock	u_pthread_mutex_lock
#define pthread_mutex_unlock	u_pthread_mutex_unlock
#define pthread_join		u_pthread_join
#define usleep			u_usleep

void pthread_create(pthread_t *t, pthread_attr_t *attr, void *(*fn)(void *), void *arg);
int pthread_mutex_init(pthread_mutex_t *lock, void *unused);
int pthread_mutex_destroy(pthread_mutex_t *lock);
int pthread_mutex_lock(pthread_mutex_t *lock);
int pthread_mutex_unlock(pthread_mutex_t *lock);
int pthread_join(pthread_t *t, void **ret);
void usleep(long usec);

#endif


/*
 * LE/BE <-> CPU conversion.
 */

static inline void put32_le(void *dst, uint32_t val)
{
#ifdef WORDS_BIGENDIAN
	uint8_t *d = dst;
	d[0] = val;
	d[1] = val >> 8;
	d[2] = val >> 16;
	d[3] = val >> 24;
#else
	memcpy(dst, &val, 4);
#endif
}

static inline void put32_be(uint8_t *dst, uint32_t val)
{
#ifndef WORDS_BIGENDIAN
	val = htonl(val);
#endif
	memcpy(dst, &val, 4);
}

static inline uint32_t get32_le(const void *src)
{
#ifdef WORDS_BIGENDIAN
	const uint8_t *s = src;
	return s[0] | (s[1] << 8) | (s[2] << 16) | (s[3] << 24);
#else
	return *(uint32_t*)src;
#endif
}

static inline uint32_t get32_be(const void *src)
{
	uint32_t val;
	memcpy(&val, src, 4);
#ifndef WORDS_BIGENDIAN
	val = ntohl(val);
#endif
	return val;
}

#define R4(R, t) R(t+0); R(t+1); R(t+2); R(t+3)
#define R16(R, t) R4(R, t+0); R4(R, t+4); R4(R, t+8); R4(R, t+12)
#define R20(R, t) R16(R, t+0); R4(R, t+16)
#define R64(R, t) R16(R, t+0); R16(R, t+16); R16(R, t+32); R16(R, t+48)

