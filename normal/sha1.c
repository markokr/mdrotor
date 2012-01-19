
/*
 * SHA1 - RFC3174
 */

#include "mdrotor.h"
#include "result.h"


DEF_FULL_RESULT(160)

struct sha1_ctx {
	union {
		uint32_t words[16];
		uint8_t raw[16 * 4];
	} buf;
	struct RotorStack stk;
	struct Result16 *res16;
	struct Result160 *res;
};
typedef struct sha1_ctx SHA1_CTX;


#define AA 0x67452301
#define BB 0xefcdab89
#define CC 0x98badcfe
#define DD 0x10325476
#define EE 0xc3d2e1f0

#define K0 0x5a827999
#define K1 0x6ed9eba1
#define K2 0x8f1bbcdc
#define K3 0xca62c1d6

#define F0z(b, c, d) ((b & c) | ((~b) & d))
#define F1(b, c, d) (b ^ c ^ d)
#define F2(b, c, d) ((b & c) | (b & d) | (c & d))
#define F3(b, c, d) (b ^ c ^ d)

#define F0(b, c, d) (d ^ (b & (c ^ d)))
#define F0b(b, c, d) ((b & c) ^ ((~b) & d))
#define F0v(b, c, d) ((b & c) + ((~b) & d))

#define F2a(b, c, d) ((b & c) | (d & (b | c)))
#define F2b(b, c, d) ((b & c) | (d & (b ^ c)))
#define F2c(b, c, d) ((b & c) + (d & (b ^ c)))
#define F2d(b, c, d) ((b & c) ^ (b & d) ^ (c & d))


#define W(n)	(buf[(n) & 15])
#define S(n, x) rol32(x, n)
//#define setW(n, val) do { W(n) = val; } while (0)
#define setW(n, val) do { *(volatile uint32_t *)&W(n) = val; } while (0)

/*
 * W(n) = val
 *   64 - 11.0
 *   32 -  9.3
 *
 * *(volatile uint32_t *)&W(n) = val
 *   64 - 10.4
 *   32 -  5.4
 */

#define SHA1(_t, fn, K) do { \
	uint32_t tmp, t = (_t); \
	if (t >= 16) { \
		tmp = W(t - 3) ^ W(t - 8) ^ W(t - 14) ^ W(t - 16); \
		setW(t, S(1, tmp)); \
	} else { \
		setW(t, ctx->buf.words[t]); \
	} \
	tmp = S(5, a) + fn(b, c, d) + e + W(t) + K; \
	e = d; d = c; c = S(30, b); b = a; a = tmp; \
} while (0)

#define SHA1R0(t) SHA1(t, F0, K0)
#define SHA1R1(t) SHA1(t, F1, K1)
#define SHA1R2(t) SHA1(t, F2, K2)
#define SHA1R3(t) SHA1(t, F3, K3)

#define REV(e) ror32((e) - EE, 30)

static void sha1_core(struct sha1_ctx * ctx)
{
	uint32_t a = AA, b = BB, c = CC, d = DD, e = EE;
	uint32_t buf[16], h[5];

	R20(SHA1R0, 0);
	R20(SHA1R1, 20);
	R20(SHA1R2, 40);

	/* SHA20(60, F3, K3); */
	R16(SHA1R3, 60);
	if (!result16_check(ctx->res16, a)) return;
	R4(SHA1R3, 76);

	h[0] = htonl(a + AA);
	h[1] = htonl(b + BB);
	h[2] = htonl(c + CC);
	h[3] = htonl(d + DD);
	h[4] = htonl(e + EE);
	if (result160_check(ctx->res, h))
		print_result(&ctx->stk, h);
}

/*
 * Standard API.
 */

static inline void set_char_fast(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	SHA1_CTX *ctx = stk->eng->priv;
#ifdef WORDS_BIGENDIAN
	ctx->buf.raw[char_pos] = c;
#else
	ctx->buf.raw[char_pos ^ 3] = c;
#endif
}

static void set_char(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	set_char_fast(stk, char_pos, c);
}

static void set_length(struct RotorStack *stk, unsigned int len)
{
	SHA1_CTX *ctx = stk->eng->priv;
	set_char(stk, len, 0x80);
	ctx->buf.words[15] = len * 8;
}

static void init(struct EngineThread *eng)
{
	SHA1_CTX *ctx = zmalloc(sizeof(*ctx));
	eng->priv = ctx;

	stack_init(eng, &ctx->stk, 0);

	ctx->res = new_result160();
	ctx->res16 = new_result16();
}

static void release(struct EngineThread *eng)
{
	SHA1_CTX *ctx = eng->priv;
	result160_free(ctx->res);
	result16_free(ctx->res16);
	free(ctx);
}

static void add_hash(struct EngineThread *eng, const void *hash)
{
	SHA1_CTX *ctx = eng->priv;
	const uint8_t *p = hash;
	result160_add(ctx->res, hash);
	result16_add(ctx->res16, REV(get32_be(p + 16)));
}

static void run(struct EngineThread *eng)
{
	SHA1_CTX *ctx = eng->priv;

	result160_sort(ctx->res);

	while (eng->active) {
		sha1_core(ctx);
		stack_turn(&ctx->stk, set_char_fast);
	}
}

static const char * const samples[] = {
	"f10e2821bbbea527ea02200352313bc059445190", // asd
	"817d5ac7e544e872f744d175cc8b982f5cdf5a82", // fooz
	"4d852f733c7f8bf4149c3fcc366cb60cdc2a1a7c", // zaaf
	"c1a366b0f0fb0f62ad8ca310d1dd2d1ba69b7c27", // bafaz
	NULL,
};

const struct EngineInfo eng_sha1plain = {
	.eng_name = "sha1plain", .algo_name = "sha1",
	.hash_len = 20,
	.init = init,
	.release = release,
	.add_hash = add_hash,
	.run = run,
	.set_char = set_char,
	.set_length = set_length,
	.sample_list = samples,
};

