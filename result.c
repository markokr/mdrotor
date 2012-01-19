
#define MIN_BSEARCH 10

/*
 * any-bit result
 */

typedef int (*cmp_f)(const void *a, const void *b);
#define DEF_CMP(x) \
static int cmp_ ## x(const void *a, const void *b) { return memcmp(a, b, x); }

DEF_CMP(4) // 32
DEF_CMP(16) // 128
DEF_CMP(20) // 160
DEF_CMP(32) // 256
DEF_CMP(64) // 512

static get_cmp(int size) {
	if (size == 4) return cmp_4;
	if (size == 16) return cmp_16;
	if (size == 20) return cmp_20;
	if (size == 32) return cmp_32;
	if (size == 64) return cmp_64;
	die("undefined size");
}

struct FullResult {
	uint8_t *buf;
	unsigned alloc;
	unsigned used;
	unsigned size;
};

struct FullResult *fresult_new(unsigned item_bits)
{
	struct FullResult *r = zmalloc(sizeof(struct FullResult));
	r->size = item_bits / 8;
	r->alloc = 256;
	r->buf = zmalloc(r->alloc * r->size);
	return r;
}

void fresult_add(struct FullResult *r, const void *item)
{
	if (r->used >= r->alloc) {
		void *tmp = realloc(r->buf, 2 * r->alloc * r->size);
		if (!tmp) die("no mem");
		r->buf = tmp;
		r->alloc *= 2;
	}
	memcpy(r->buf + r->size * r->used++, item, r->size);
}

static int cmp_item_full(const void *a, const void *b)
{
	return memcmp(a, b, bits / 8);
}

void fresult_sort(const struct FullResult *r)
{
	cmp_f c = get_cmp(r->size);
	if (r->used > 0)
		qsort(r->buf, r->used, r->size, c);
}

bool fresult_check(const struct FullResult *r, const void *item)
{
	cmp_f c = get_cmp(r->size);
	void *res = NULL;
	res = bsearch(item, r->buf, r->used, r->size, c);
	return res ? true : false;
}

void fresult_free(struct Result ## bits *r)
{
	free(r->buf);
	free(r);
}

