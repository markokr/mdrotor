
/*
 * SHA512, SHA384 for SSE2
 */

#include "mdrotor.h"
#include "result.h"

#define SSE2BITS 64
#include "sse2.h"

#define E0S1 28
#define E0S2 34
#define E0S3 39
#define E1S1 14
#define E1S2 18
#define E1S3 41

#define O0S1 1
#define O0S2 8
#define O0S3 7
#define O1S1 19
#define O1S2 61
#define O1S3 6

#include "sha2sse.h"

DEF_FULL_RESULT(512)

struct sha512_ctx {
	SVAL buf[16];
	SVAL final[8];
	struct RotorStack stk[2];
	struct SSResult *sres;
	struct Result512 *res;
	bool stripped;
};
typedef struct sha512_ctx SHA512_CTX;

static void check_result(SHA512_CTX *ctx)
{
	int i;
	uint64_t hash[8];
	struct RotorStack *stk;

	for (i = 0; i < 2; i++) {
		stk = &ctx->stk[i];
		if (stk->stopped)
			continue;
		hash[0] =  hton64(ctx->final[0].longs[i]);
		hash[1] =  hton64(ctx->final[1].longs[i]);
		hash[2] =  hton64(ctx->final[2].longs[i]);
		hash[3] =  hton64(ctx->final[3].longs[i]);
		hash[4] =  hton64(ctx->final[4].longs[i]);
		hash[5] =  hton64(ctx->final[5].longs[i]);
		hash[6] =  hton64(ctx->final[6].longs[i]);
		hash[7] =  hton64(ctx->final[7].longs[i]);
		if (result512_check(ctx->res, hash))
			print_result(&ctx->stk[i], hash);
	}
}

static const SVAL H384[8] = {
	C64(0xcbbb9d5dc1059ed8ULL), C64(0x629a292a367cd507ULL), C64(0x9159015a3070dd17ULL), C64(0x152fecd8f70e5939ULL),
	C64(0x67332667ffc00b31ULL), C64(0x8eb44a8768581511ULL), C64(0xdb0c2e0d64f98fa7ULL), C64(0x47b5481dbefa4fa4ULL),
};

static const SVAL H512[8] = {
	C64(0x6a09e667f3bcc908ULL), C64(0xbb67ae8584caa73bULL), C64(0x3c6ef372fe94f82bULL), C64(0xa54ff53a5f1d36f1ULL),
	C64(0x510e527fade682d1ULL), C64(0x9b05688c2b3e6c1fULL), C64(0x1f83d9abfb41bd6bULL), C64(0x5be0cd19137e2179ULL),
};

static const SVAL K[80] = {
	C64(0x428a2f98d728ae22ULL), C64(0x7137449123ef65cdULL), C64(0xb5c0fbcfec4d3b2fULL), C64(0xe9b5dba58189dbbcULL),
	C64(0x3956c25bf348b538ULL), C64(0x59f111f1b605d019ULL), C64(0x923f82a4af194f9bULL), C64(0xab1c5ed5da6d8118ULL),
	C64(0xd807aa98a3030242ULL), C64(0x12835b0145706fbeULL), C64(0x243185be4ee4b28cULL), C64(0x550c7dc3d5ffb4e2ULL),
	C64(0x72be5d74f27b896fULL), C64(0x80deb1fe3b1696b1ULL), C64(0x9bdc06a725c71235ULL), C64(0xc19bf174cf692694ULL),
	C64(0xe49b69c19ef14ad2ULL), C64(0xefbe4786384f25e3ULL), C64(0x0fc19dc68b8cd5b5ULL), C64(0x240ca1cc77ac9c65ULL),
	C64(0x2de92c6f592b0275ULL), C64(0x4a7484aa6ea6e483ULL), C64(0x5cb0a9dcbd41fbd4ULL), C64(0x76f988da831153b5ULL),
	C64(0x983e5152ee66dfabULL), C64(0xa831c66d2db43210ULL), C64(0xb00327c898fb213fULL), C64(0xbf597fc7beef0ee4ULL),
	C64(0xc6e00bf33da88fc2ULL), C64(0xd5a79147930aa725ULL), C64(0x06ca6351e003826fULL), C64(0x142929670a0e6e70ULL),
	C64(0x27b70a8546d22ffcULL), C64(0x2e1b21385c26c926ULL), C64(0x4d2c6dfc5ac42aedULL), C64(0x53380d139d95b3dfULL),
	C64(0x650a73548baf63deULL), C64(0x766a0abb3c77b2a8ULL), C64(0x81c2c92e47edaee6ULL), C64(0x92722c851482353bULL),
	C64(0xa2bfe8a14cf10364ULL), C64(0xa81a664bbc423001ULL), C64(0xc24b8b70d0f89791ULL), C64(0xc76c51a30654be30ULL),
	C64(0xd192e819d6ef5218ULL), C64(0xd69906245565a910ULL), C64(0xf40e35855771202aULL), C64(0x106aa07032bbd1b8ULL),
	C64(0x19a4c116b8d2d0c8ULL), C64(0x1e376c085141ab53ULL), C64(0x2748774cdf8eeb99ULL), C64(0x34b0bcb5e19b48a8ULL),
	C64(0x391c0cb3c5c95a63ULL), C64(0x4ed8aa4ae3418acbULL), C64(0x5b9cca4f7763e373ULL), C64(0x682e6ff3d6b2b8a3ULL),
	C64(0x748f82ee5defb2fcULL), C64(0x78a5636f43172f60ULL), C64(0x84c87814a1f0ab72ULL), C64(0x8cc702081a6439ecULL),
	C64(0x90befffa23631e28ULL), C64(0xa4506cebde82bde9ULL), C64(0xbef9a3f7b2c67915ULL), C64(0xc67178f2e372532bULL),
	C64(0xca273eceea26619cULL), C64(0xd186b8c721c0c207ULL), C64(0xeada7dd6cde0eb1eULL), C64(0xf57d4f7fee6ed178ULL),
	C64(0x06f067aa72176fbaULL), C64(0x0a637dc5a2c898a6ULL), C64(0x113f9804bef90daeULL), C64(0x1b710b35131c471bULL),
	C64(0x28db77f523047d84ULL), C64(0x32caab7b40c72493ULL), C64(0x3c9ebe0a15c9bebcULL), C64(0x431d67c49c100d4cULL),
	C64(0x4cc5d4becb3e42b6ULL), C64(0x597f299cfc657e2aULL), C64(0x5fcb6fab3ad6faecULL), C64(0x6c44198c4a475817ULL),
};

static void sha512_core(struct sha512_ctx * ctx, const SVAL *iv)
{
	__m128i a, b, c, d, e, f, g, h;
	SVAL buf[80];

	R16(COPY, 0);
	R64(PREPARE, 16);

	a = sval_load(&iv[0]);
	b = sval_load(&iv[1]);
	c = sval_load(&iv[2]);
	d = sval_load(&iv[3]);
	e = sval_load(&iv[4]);
	f = sval_load(&iv[5]);
	g = sval_load(&iv[6]);
	h = sval_load(&iv[7]);

	R64(SHA2ROUND, 0);

	R4(SHA2ROUND, 64);
	R4(SHA2ROUND, 68);
	R4(SHA2ROUND, 72);
	SHA2ROUND(76);
	if (!ctx->stripped && !ssresult_check64(ctx->sres, e)) return;
	SHA2ROUND(77);
	SHA2ROUND(78);
	if (ctx->stripped && !ssresult_check64(ctx->sres, e)) return;
	SHA2ROUND(79);


	FINAL(0, a);
	FINAL(1, b);
	FINAL(2, c);
	FINAL(3, d);
	FINAL(4, e);
	FINAL(5, f);
	if (!ctx->stripped) {
		FINAL(6, g);
		FINAL(7, h);
	}
	check_result(ctx);
}

static inline uint64_t REV512(struct sha512_ctx *ctx, const void *hash) {
	const uint64_t *p = hash;
	if (ctx->stripped)
		return ntoh64(p[5]) - H384[5].longs[0];
	else
		return ntoh64(p[7]) - H512[7].longs[0];
}

/*
 * Standard API.
 */

static inline void set_char_fast(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	SHA512_CTX *ctx = stk->eng->priv;
	int wpos = char_pos / 8;
	int bpos = (char_pos & 7) ^ 7;
	ctx->buf[wpos].raw64[stk->id][bpos] = c;
}

static void set_char(struct RotorStack *stk, unsigned int char_pos, unsigned int c)
{
	set_char_fast(stk, char_pos, c);
}

static void set_length(struct RotorStack *stk, unsigned int len)
{
	SHA512_CTX *ctx = stk->eng->priv;
	ctx->buf[len / 8].raw64[stk->id][(len & 7) ^ 7] = 0x80;
	ctx->buf[15].longs[stk->id] = len * 8;
}

static void init512(struct EngineThread *eng)
{
	SHA512_CTX *ctx = _mm_malloc(sizeof(*ctx), 16);
	eng->priv = ctx;
	memset(ctx, 0, sizeof(*ctx));

	stack_init(eng, &ctx->stk[0], 0);
	stack_init(eng, &ctx->stk[1], 1);

	ctx->res = new_result512();
	ctx->sres = ssresult_new();
}

static void init384(struct EngineThread *eng)
{
	SHA512_CTX *ctx;
	init512(eng);
	ctx = eng->priv;
	ctx->stripped = true;
}

static void release(struct EngineThread *eng)
{
	SHA512_CTX *ctx = eng->priv;
	result512_free(ctx->res);
	ssresult_free(ctx->sres);
	_mm_free(ctx);
}

static void add_hash(struct EngineThread *eng, const void *hash)
{
	SHA512_CTX *ctx = eng->priv;
	ssresult_add64(ctx->sres, REV512(ctx, hash));
	result512_add(ctx->res, hash);
}

static void run(struct EngineThread *eng)
{
	SHA512_CTX *ctx = eng->priv;
	const SVAL *iv = ctx->stripped ? H384 : H512;

	result512_sort(ctx->res);

	while (eng->active) {
		sha512_core(ctx, iv);
		stack_turn(&ctx->stk[0], set_char_fast);
		stack_turn(&ctx->stk[1], set_char_fast);
	}
}

static const char * const samples512[] = {
	"e54ee7e285fbb0275279143abc4c554e5314e7b417ecac83a5984a964facbaad"
	"68866a2841c3e83ddf125a2985566261c4014f9f960ec60253aebcda9513a9b4", // asd
	"e44da7be76957a380f541ac6d28c0b2554c76aa8b36c5040c81596bc844d010c"
	"46dcedce88e0c2d0c88be8bfb4f65d105e498a910289cda170d36552d57fd33d", // fooz
	"64eb157177a341cd366245371dcd0975700e002773f88c773cd0f7cfd888bd0e"
	"09fbb723393a44d9fdb9a4a06c34fc74f672f435e3328757b3d9e3fcd1fe873c", // bafaz
	NULL
};

static const char * const samples384[] = {
	"91389ee5448e9d7a00f2f250e3d83beff18f1177a04bd0a2019c27b0493bfa072130dfd1625c7b835d0bb008895272f8",
	"2966109d2670ddc3ba771d2e02e0685e95eaf50c5ecc6fd50ddf08acdcf5b4855848fb6a015a413bc37968505ebce869",
	"2719566d41ca3f8503fee2db4fef0ec5cbcf079e33614c1c6ce76a033145d91e2ffc51efcfb4635a89c3727e05d1d7b4",
	NULL
};

const struct EngineInfo eng_sha512sse = {
	.eng_name = "sha512sse", .algo_name = "sha512",
	.hash_len = 64,
	.init = init512,
	.release = release,
	.add_hash = add_hash,
	.run = run,
	.set_char = set_char,
	.set_length = set_length,
	.sample_list = samples512,
};

const struct EngineInfo eng_sha384sse = {
	.eng_name = "sha384sse", .algo_name = "sha384",
	.hash_len = 384 / 8,
	.init = init384,
	.release = release,
	.add_hash = add_hash,
	.run = run,
	.set_char = set_char,
	.set_length = set_length,
	.sample_list = samples384,
};

