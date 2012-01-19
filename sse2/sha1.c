
/*
 * SHA1 - RFC3174
 */

#include "mdrotor.h"
#include "result.h"
#include "sse2.h"

DEF_FULL_RESULT(160)

struct sha1_ctx {
	SVAL buf[16];
	SVAL final[5];
	struct RotorStack stk[4];
	struct SSResult *sres;
	struct Result160 *res;
};
typedef struct sha1_ctx SHA1_CTX;

static void check_result(SHA1_CTX *ctx)
{
	int i;
	uint32_t hash[5];
	struct RotorStack *stk;

	for (i = 0; i < 4; i++) {
		stk = &ctx->stk[i];
		if (stk->stopped)
			continue;
		hash[0] =  htonl(ctx->final[0].words[i]);
		hash[1] =  htonl(ctx->final[1].words[i]);
		hash[2] =  htonl(ctx->final[2].words[i]);
		hash[3] =  htonl(ctx->final[3].words[i]);
		hash[4] =  htonl(ctx->final[4].words[i]);
		if (result160_check(ctx->res, hash))
			print_result(&ctx->stk[i], hash);
	}
}

#define AA 0x67452301
#define BB 0xefcdab89
#define CC 0x98badcfe
#define DD 0x10325476
#define EE 0xc3d2e1f0

#define K0 0x5a827999
#define K1 0x6ed9eba1
#define K2 0x8f1bbcdc
#define K3 0xca62c1d6

#define REV(e) ror32((e) - EE, 30)

/* F0: (x & y) | ((~x) & z) */
/* F0a:: (x & y) | ((~x) & z) */
#define F0(x,y,z) OR(AND(x, y), ANDNOT(x,z))

/* F1: (x ^ y ^ z) */
#define F1(x,y,z) XOR(x, XOR(y, z))

/* F2: (x & y) | (x & z) | (y & z) */
#define F2(x,y,z) OR(AND(x,y), OR(AND(x,z), AND(y,z)))

/* F3: (x ^ y ^ z) */
#define F3(x,y,z) XOR(x, XOR(y,z))

#define W(n)		sval_load(&buf[(n) & 15])
#define setW(n, v)	sval_store(&buf[(n) & 15], v)
#define S(n, x)		ROL(x, n)

/* tmp = S(5, a) + fn(b, c, d) + e + W(t) + K; */
/* e = d; d = c; c = S(30, b); b = a; a = tmp; */
#define SHA1(t, fn, K) do { \
	w = ((t) >= 16) ? prepare(t, buf) \
			: sval_load(&ctx->buf[t]); \
	if ((t) < 80 - 3) setW(t, w); \
	v1 = ADD(S(5, a), ADD(ADD(ADD(e, K), fn(b,c,d)), w)); \
	e = d; d = c; c = S(30, b); b = a; a = v1; \
} while (0)

/* W(t) = S(1, (W(t - 3) ^ W(t - 8) ^ W(t - 14) ^ W(t - 16)) */
static inline __m128i prepare(int t, SVAL *buf)
{
	__m128i v = XOR(XOR(XOR(W(t - 3), W(t - 8)), W(t - 14)), W(t - 16));
	return S(1, v);
}


#define SHA1R0(t) SHA1(t, F0, k0)
#define SHA1R1(t) SHA1(t, F1, k1)
#define SHA1R2(t) SHA1(t, F2, k2)
#define SHA1R3(t) SHA1(t, F3, k3)

#define FINAL(idx, val, old) \
	sval_store(&ctx->final[idx], ADD(val, SET1(old)))


static void sha1_core(struct sha1_ctx * ctx)
{
	__m128i a, b, c, d, e;
	__m128i k0, k1, k2, k3;
	__m128i v1, w;
	SVAL buf[16];

	a = SET1(AA);
	b = SET1(BB);
	c = SET1(CC);
	d = SET1(DD);
	e = SET1(EE);

	k0 = SET1(K0);
	R20(SHA1R0, 0);

	k1 = SET1(K1);
	R20(SHA1R1, 20);

	k2 = SET1(K2);
	R20(SHA1R2, 40);

	k3 = SET1(K3);
	R16(SHA1R3, 60);
	if (!ssresult_check(ctx->sres, a)) return;
	R4(SHA1R3, 76);

	FINAL(0, a, AA);
	FINAL(1, b, BB);
	FINAL(2, c, CC);
	FINAL(3, d, DD);
	FINAL(4, e, EE);
	check_result(ctx);
}

/*
 * Standard API.
 */

static inline void set_char_fast(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	SHA1_CTX *ctx = stk->eng->priv;
	int wpos = char_pos / 4;
	int bpos = (char_pos & 3) ^ 3;
	ctx->buf[wpos].raw32[stk->id][bpos] = c;
}

static void set_char(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	set_char_fast(stk, char_pos, c);
}

static void set_length(struct RotorStack *stk, unsigned int len)
{
	SHA1_CTX *ctx = stk->eng->priv;
	ctx->buf[len / 4].raw32[stk->id][(len & 3) ^ 3] = 0x80;
	ctx->buf[15].words[stk->id] = len * 8;
}

static void init(struct EngineThread *eng)
{
	SHA1_CTX *ctx = _mm_malloc(sizeof(*ctx), 16);
	eng->priv = ctx;
	memset(ctx, 0, sizeof(*ctx));

	stack_init(eng, &ctx->stk[0], 0);
	stack_init(eng, &ctx->stk[1], 1);
	stack_init(eng, &ctx->stk[2], 2);
	stack_init(eng, &ctx->stk[3], 3);

	ctx->res = new_result160();
	ctx->sres = ssresult_new();
}

static void release(struct EngineThread *eng)
{
	SHA1_CTX *ctx = eng->priv;
	result160_free(ctx->res);
	ssresult_free(ctx->sres);
	_mm_free(ctx);
}

static void add_hash(struct EngineThread *eng, const void *hash)
{
	SHA1_CTX *ctx = eng->priv;
	const uint32_t *h = hash;
	ssresult_add32(ctx->sres, REV(ntohl(h[4])));
	result160_add(ctx->res, hash);
}

static void run(struct EngineThread *eng)
{
	SHA1_CTX *ctx = eng->priv;

	result160_sort(ctx->res);
	while (eng->active) {
		sha1_core(ctx);
		stack_turn(&ctx->stk[0], set_char_fast);
		stack_turn(&ctx->stk[1], set_char_fast);
		stack_turn(&ctx->stk[2], set_char_fast);
		stack_turn(&ctx->stk[3], set_char_fast);
	}
}

static const char * const samples[] = {
	"f10e2821bbbea527ea02200352313bc059445190", // asd
	"817d5ac7e544e872f744d175cc8b982f5cdf5a82", // fooz
	"4d852f733c7f8bf4149c3fcc366cb60cdc2a1a7c", // zaaf
	"c1a366b0f0fb0f62ad8ca310d1dd2d1ba69b7c27", // bafaz
	NULL,
};

const struct EngineInfo eng_sha1sse = {
	.algo_name = "sha1", .eng_name = "sha1sse",
	.hash_len = 20,
	.init = init,
	.release = release,
	.add_hash = add_hash,
	.run = run,
	.set_char = set_char,
	.set_length = set_length,
	.sample_list = samples,
};

