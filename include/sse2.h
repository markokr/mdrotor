

/*
 * Common SSE2 defs.
 */

#include <emmintrin.h>

#define _SSE_ALIGN __attribute__((aligned(16)))

union sse_value {
	__m128i sse;
	uint64_t longs[2];
	uint32_t words[4];
	uint8_t raw8[16];
	uint8_t raw32[4][4];
	uint8_t raw64[2][8];
} _SSE_ALIGN;
typedef union sse_value SVAL;

#define C32(x) { .words = {x,x,x,x} }
#define C64(x) { .longs = {x,x} }

static inline __m128i sval_load(const SVAL *sval) { return _mm_load_si128(&sval->sse); }
static inline void sval_store(SVAL *sval, __m128i v) { _mm_store_si128(&sval->sse, v); }

/* rol: (v << s) | (v >> (32 - s)) */
static inline __m128i rol_epi32(__m128i v, int s)
{
	__m128i v1 = _mm_slli_epi32(v, s);
	__m128i v2 = _mm_srli_epi32(v, 32 - s);
	return _mm_xor_si128(v1, v2);
}
#define ror_epi32(v,s) rol_epi32(v, 32 - (s))

static inline __m128i rol_epi64(__m128i v, int s)
{
	__m128i v1 = _mm_slli_epi64(v, s);
	__m128i v2 = _mm_srli_epi64(v, 64 - s);
	return _mm_xor_si128(v1, v2);
}
#define ror_epi64(v,s) rol_epi64(v, 64 - (s))

/*
 * readable ops
 */
#ifndef SSE2BITS
#define SSE2BITS 32
#endif
#if SSE2BITS != 32 && SSE2BITS != 64
#error bad value for SSE2BITS
#endif

#define XOR(x, y) _mm_xor_si128(x, y)
#define AND(x, y) _mm_and_si128(x, y)
#define OR(x, y) _mm_or_si128(x, y)
#define ANDNOT(x, y) _mm_andnot_si128(x, y)

#if SSE2BITS == 64
#define ADD(x, y) _mm_add_epi64(x, y)
#define SHR(x, y) _mm_srli_epi64(x, y)
#define SHL(x, y) _mm_slli_epi64(x, y)
#define SET1(x) _mm_set1_epi64(x)

#if 1
#define ROR(x,s) ror_epi64(x,s)
#define ROL(x,s) rol_epi64(x,s)
#else
#define ROR(x, s) XOR(SHR(x, s), SHL(x, 64-(s)))
#define ROL(x, s) XOR(SHL(x, s), SHR(x, 64-(s)))
#endif

#else // SSE2BITS == 32

#define ADD(x, y) _mm_add_epi32(x, y)
#define SHR(x, y) _mm_srli_epi32(x, y)
#define SHL(x, y) _mm_slli_epi32(x, y)
#define SET1(x) _mm_set1_epi32(x)

#if 1
#define ROR(x,s) ror_epi32(x,s)
#define ROL(x,s) rol_epi32(x,s)
#else
#define ROR(x, s) XOR(SHR(x, s), SHL(x, 32-(s)))
#define ROL(x, s) XOR(SHL(x, s), SHR(x, 32-(s)))
#endif

#endif

/*
 * 32bit value cache
 */

#define _SSRESULT_BITS (14)
#define _SSRESULT_REVBITS (32 - _SSRESULT_BITS)
#define _SSRESULT_CNT  (1 << _SSRESULT_BITS)
#define _SSRESULT_  (1 << _SSRESULT_BITS)
struct SSResult { uint8_t map[_SSRESULT_CNT]; };
static inline void ssresult_add(struct SSResult *r, __m128i v)
{
	SVAL tmp;
	sval_store(&tmp, _mm_srli_epi32(v, _SSRESULT_REVBITS));
	r->map[tmp.words[0]] = 1;
	r->map[tmp.words[1]] = 1;
	r->map[tmp.words[2]] = 1;
	r->map[tmp.words[3]] = 1;
}
static inline void ssresult_add32(struct SSResult *r, uint32_t v)
{
	r->map[v >> _SSRESULT_REVBITS] = 1;
}
static inline bool ssresult_check(struct SSResult *r, __m128i v)
{
	SVAL tmp;
	sval_store(&tmp, _mm_srli_epi32(v, _SSRESULT_REVBITS));
	if ((r->map[tmp.words[0]] | r->map[tmp.words[1]] |
	     r->map[tmp.words[2]] | r->map[tmp.words[3]]) == 0)
		return false;
	return true;
}

static inline void ssresult_add64(struct SSResult *r, uint64_t v)
{
	r->map[v >> (32 + _SSRESULT_REVBITS)] = 1;
}

static inline bool ssresult_check64(struct SSResult *r, __m128i v)
{
	SVAL tmp;
	sval_store(&tmp, _mm_srli_epi64(v, 32 + _SSRESULT_REVBITS));
	if ((r->map[tmp.words[0]] | r->map[tmp.words[2]]) == 0)
		return false;
	return true;
}

static inline struct SSResult *ssresult_new(void) { return zmalloc(sizeof(struct SSResult)); }
static inline void ssresult_free(struct SSResult *r) { free(r); }
static inline void ssresult_clear(struct SSResult *r) { memset(r, 0, sizeof(*r)); }


/*
 * old code
 */

static inline void result16_add_sse(struct Result16 *res, __m128i v)
{
	SVAL tmp[2], val;
	_mm_store_si128(&val.sse, v);
	_mm_store_si128(&tmp[0].sse, _mm_srli_epi32(v, 16 + 2 + 3));
	v = _mm_slli_epi32(v, 16 - 2 - 3);
	v = _mm_srli_epi32(v, 16 + 16 - 2 - 3);
	_mm_store_si128(&tmp[1].sse, v);

	res->map[tmp[0].words[0]] |= (1 << tmp[1].words[0]);
	res->map[tmp[0].words[1]] |= (1 << tmp[1].words[1]);
	res->map[tmp[0].words[2]] |= (1 << tmp[1].words[2]);
	res->map[tmp[0].words[3]] |= (1 << tmp[1].words[3]);
}

static inline bool result16_check_sse(struct Result16 *res, __m128i v)
{
	SVAL tmp[2];
	_mm_store_si128(&tmp[0].sse, _mm_srli_epi32(v, 16 + 2 + 3));
	if ((res->map[tmp[0].words[0]] | res->map[tmp[0].words[1]] |
	     res->map[tmp[0].words[2]] | res->map[tmp[0].words[3]]) == 0)
		return false;
	return true;
}


/*
 * dumping
 */

static inline void dump_svals(const char *desc, int cnt, SVAL *list)
{
	int i;
	printf("%s [%d]:\n", desc, cnt);
	for (i = 0; i < cnt; i++) {
		uint32_t *w = list[i].words;
		printf("%02d: %08x %08x %08x %08x\n", i, w[0], w[1], w[2], w[3]);
	}
}


