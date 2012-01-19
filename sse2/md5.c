#include "mdrotor.h"
#include "result.h"
#include "sse2.h"

DEF_FULL_RESULT(128)

struct sse_ctx {
	SVAL buf[16];
	SVAL state[4];
	struct RotorStack stk[4];
	struct SSResult *sres;
	struct Result128 *res;
} _SSE_ALIGN;

typedef struct sse_ctx SSE_CTX;

static void check_result(SSE_CTX *ctx)
{
	int i;
	uint32_t hash[4];
	struct RotorStack *stk;

	for (i = 0; i < 4; i++) {
		stk = &ctx->stk[i];
		if (stk->stopped)
			continue;
		hash[0] =  ctx->state[0].words[i];
		hash[1] =  ctx->state[1].words[i];
		hash[2] =  ctx->state[2].words[i];
		hash[3] =  ctx->state[3].words[i];
		if (result128_check(ctx->res, hash))
			print_result(&ctx->stk[i], hash);
	}
}

/*
 * SSE2 based MD5 core.
 */

#define AA 0x67452301
#define BB 0xefcdab89
#define CC 0x98badcfe
#define DD 0x10325476

/* F: ((X & Y) | ((~X) & Z)) */
/* Fa: (z ^ (x & (y ^ z))) */
#define F(x,y,z) XOR(z, AND(x, XOR(y,z)))

/* G: ((X & Z) | (Y & (~Z))) */
/* Ga: (y ^ (z & (x ^ y))) */
#define G(x,y,z) OR(AND(x, z), ANDNOT(z, y))

/* H: (X ^ Y ^ Z) */
#define H(x,y,z) XOR(x, XOR(y, z))

/* I: (Y ^ (X | (~Z))) */
#define I(x,y,z) XOR(y, OR(x, XOR(z, SET1(-1))))

/* a = b + rol(a + fn(b, c, d) + X[k] + T_i, s); */
#define OP(fn, a, b, c, d, k, s, T_i) \
	a = ADD(b, ROL(ADD(ADD(ADD(SET1(T_i), a), sval_load(&X[k])), fn(b, c, d)), s))

#define FINAL(idx, val, old) sval_store(&ctx->state[idx], ADD(val, SET1(old)))

static void md5_core(SSE_CTX *ctx)
{
	const SVAL *X = ctx->buf;
	__m128i a, b, c, d;
	a = _mm_set1_epi32(AA);
	b = _mm_set1_epi32(BB);
	c = _mm_set1_epi32(CC);
	d = _mm_set1_epi32(DD);
	/* Round 1. */
	OP(F, a, b, c, d, 0, 7, 0xd76aa478);
	OP(F, d, a, b, c, 1, 12, 0xe8c7b756);
	OP(F, c, d, a, b, 2, 17, 0x242070db);
	OP(F, b, c, d, a, 3, 22, 0xc1bdceee);
	OP(F, a, b, c, d, 4, 7, 0xf57c0faf);
	OP(F, d, a, b, c, 5, 12, 0x4787c62a);
	OP(F, c, d, a, b, 6, 17, 0xa8304613);
	OP(F, b, c, d, a, 7, 22, 0xfd469501);
	OP(F, a, b, c, d, 8, 7, 0x698098d8);
	OP(F, d, a, b, c, 9, 12, 0x8b44f7af);
	OP(F, c, d, a, b, 10, 17, 0xffff5bb1);
	OP(F, b, c, d, a, 11, 22, 0x895cd7be);
	OP(F, a, b, c, d, 12, 7, 0x6b901122);
	OP(F, d, a, b, c, 13, 12, 0xfd987193);
	OP(F, c, d, a, b, 14, 17, 0xa679438e);
	OP(F, b, c, d, a, 15, 22, 0x49b40821);
	/* Round 2. */
	OP(G, a, b, c, d, 1, 5, 0xf61e2562);
	OP(G, d, a, b, c, 6, 9, 0xc040b340);
	OP(G, c, d, a, b, 11, 14, 0x265e5a51);
	OP(G, b, c, d, a, 0, 20, 0xe9b6c7aa);
	OP(G, a, b, c, d, 5, 5, 0xd62f105d);
	OP(G, d, a, b, c, 10, 9, 0x02441453);
	OP(G, c, d, a, b, 15, 14, 0xd8a1e681);
	OP(G, b, c, d, a, 4, 20, 0xe7d3fbc8);
	OP(G, a, b, c, d, 9, 5, 0x21e1cde6);
	OP(G, d, a, b, c, 14, 9, 0xc33707d6);
	OP(G, c, d, a, b, 3, 14, 0xf4d50d87);
	OP(G, b, c, d, a, 8, 20, 0x455a14ed);
	OP(G, a, b, c, d, 13, 5, 0xa9e3e905);
	OP(G, d, a, b, c, 2, 9, 0xfcefa3f8);
	OP(G, c, d, a, b, 7, 14, 0x676f02d9);
	OP(G, b, c, d, a, 12, 20, 0x8d2a4c8a);
	/* Round 3. */
	OP(H, a, b, c, d, 5, 4, 0xfffa3942);
	OP(H, d, a, b, c, 8, 11, 0x8771f681);
	OP(H, c, d, a, b, 11, 16, 0x6d9d6122);
	OP(H, b, c, d, a, 14, 23, 0xfde5380c);
	OP(H, a, b, c, d, 1, 4, 0xa4beea44);
	OP(H, d, a, b, c, 4, 11, 0x4bdecfa9);
	OP(H, c, d, a, b, 7, 16, 0xf6bb4b60);
	OP(H, b, c, d, a, 10, 23, 0xbebfbc70);
	OP(H, a, b, c, d, 13, 4, 0x289b7ec6);
	OP(H, d, a, b, c, 0, 11, 0xeaa127fa);
	OP(H, c, d, a, b, 3, 16, 0xd4ef3085);
	OP(H, b, c, d, a, 6, 23, 0x04881d05);
	OP(H, a, b, c, d, 9, 4, 0xd9d4d039);
	OP(H, d, a, b, c, 12, 11, 0xe6db99e5);
	OP(H, c, d, a, b, 15, 16, 0x1fa27cf8);
	OP(H, b, c, d, a, 2, 23, 0xc4ac5665);
	/* Round 4. */
	OP(I, a, b, c, d, 0, 6, 0xf4292244);
	OP(I, d, a, b, c, 7, 10, 0x432aff97);
	OP(I, c, d, a, b, 14, 15, 0xab9423a7);
	OP(I, b, c, d, a, 5, 21, 0xfc93a039);
	OP(I, a, b, c, d, 12, 6, 0x655b59c3);
	OP(I, d, a, b, c, 3, 10, 0x8f0ccc92);
	OP(I, c, d, a, b, 10, 15, 0xffeff47d);
	OP(I, b, c, d, a, 1, 21, 0x85845dd1);
	OP(I, a, b, c, d, 8, 6, 0x6fa87e4f);
	OP(I, d, a, b, c, 15, 10, 0xfe2ce6e0);
	OP(I, c, d, a, b, 6, 15, 0xa3014314);
	OP(I, b, c, d, a, 13, 21, 0x4e0811a1);
	OP(I, a, b, c, d, 4, 6, 0xf7537e82);
	if (!ssresult_check(ctx->sres, a)) return;
	OP(I, d, a, b, c, 11, 10, 0xbd3af235);
	OP(I, c, d, a, b, 2, 15, 0x2ad7d2bb);
	OP(I, b, c, d, a, 9, 21, 0xeb86d391);

	FINAL(0, a, AA);
	FINAL(1, b, BB);
	FINAL(2, c, CC);
	FINAL(3, d, DD);
	check_result(ctx);
}


/*
 * Standard API.
 */

static inline void set_char_fast(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	SSE_CTX *ctx = stk->eng->priv;
	int wpos = char_pos / 4;
	int bpos = char_pos & 3;
	ctx->buf[wpos].raw32[stk->id][bpos] = c;
}

static void set_char(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	set_char_fast(stk, char_pos, c);
}

static void set_length(struct RotorStack *stk, unsigned int len)
{
	SSE_CTX *ctx = stk->eng->priv;
	set_char(stk, len, 0x80);
	ctx->buf[14].words[stk->id] = len * 8;
}

static void init(struct EngineThread *eng)
{
	SSE_CTX *ctx = _mm_malloc(sizeof(*ctx), 16);
	memset(ctx, 0, sizeof(*ctx));
	eng->priv = ctx;

	stack_init(eng, &ctx->stk[0], 0);
	stack_init(eng, &ctx->stk[1], 1);
	stack_init(eng, &ctx->stk[2], 2);
	stack_init(eng, &ctx->stk[3], 3);

	ctx->res = new_result128();
	ctx->sres = ssresult_new();
}

static void release(struct EngineThread *eng)
{
	SSE_CTX *ctx = eng->priv;
	result128_free(ctx->res);
	ssresult_free(ctx->sres);
	_mm_free(ctx);
}

static void add_hash(struct EngineThread *eng, const void *hash)
{
	SSE_CTX *ctx = eng->priv;
	const uint32_t *h = hash;
	ssresult_add32(ctx->sres, h[0] - AA);
	result128_add(ctx->res, hash);
}

static void run(struct EngineThread *eng)
{
	SSE_CTX *ctx = eng->priv;

	result128_sort(ctx->res);
	while (eng->active) {
		md5_core(ctx);

		stack_turn(&ctx->stk[0], set_char_fast);
		stack_turn(&ctx->stk[1], set_char_fast);
		stack_turn(&ctx->stk[2], set_char_fast);
		stack_turn(&ctx->stk[3], set_char_fast);
	}
}

static const char * const samples[] = {
	"7815696ecbf1c96e6894b779456d330e", // asd
	"a620be1dd85655b390313d66272bf4a1", // fooz
	"6caf2410f6f1f20e80a993fb739b69aa", // bafaz
	NULL,
};

const struct EngineInfo eng_md5sse = {
	.algo_name = "md5", .eng_name = "md5sse",
	.hash_len = 16,
	.init = init,
	.release = release,
	.add_hash = add_hash,
	.run = run,
	.set_char = set_char,
	.set_length = set_length,
	.sample_list = samples,
};

