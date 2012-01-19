
#define MIN_BSEARCH 10

#if 0
/*
 * 8-bit result
 */

struct Result8 {
	unsigned char map[256];
};
static inline struct Result8 *new_result8(void) {
	return zmalloc(sizeof(struct Result8));
}
static inline void result8_add(struct Result8 *r, uint8_t c) {
	r->map[c] = 1;
}
static inline bool result8_check(const struct Result8 *r, uint8_t c) {
	return r->map[c];
}
static inline void result8_free(struct Result8 *r) {
	free(r);
}
#endif

/*
 * 16bit result
 */

#define R16BITS  17
#define R16MASK  ((1 << R16BITS) - 1)

#define _r16pos(x) ((x & R16MASK) / (4*8))
#define _r16bit(x) ((x) & (4*8 - 1))
struct Result16 {
	uint32_t map[(1 << R16BITS) / (4*8)];
};
static inline void result16_add(struct Result16 *r, uint32_t x) {
	r->map[_r16pos(x)] |= (1 << _r16bit(x));
}
static inline bool result16_check(const struct Result16 *r, uint32_t x) {
	if (!r->map[_r16pos(x)])
		return false;
	return (r->map[_r16pos(x)] & (1 << _r16bit(x))) > 0;
}

static inline struct Result16 *new_result16(void) {
	return zmalloc(sizeof(struct Result16));
}
static inline void result16_free(struct Result16 *r) {
	free(r);
}

/*
 * any-bit result
 */

static inline const void *
inline_bsearch(const void *item, const void *base, int n, int size,
	     int (*cmp)(const void *a, const void *b))
{
	const uint8_t *p = base;
	if (n < MIN_BSEARCH) {
		while (n-- > 0) {
			if (cmp(item, p) == 0)
				return p;
			p += size;
		}
		return NULL;
	} else {
		return bsearch(item, base, n, size, cmp);
	}
}

//#define bsearch inline_bsearch

struct Result32 {
	uint32_t *buf;
	unsigned alloc;
	unsigned used;
};
static inline struct Result32 *new_result32(void) {
	struct Result32 *r = zmalloc(sizeof(struct Result32));
	r->buf = zmalloc(256 * 4);
	r->alloc = 256;
	return r;
}
static inline void result32_add(struct Result32 *r, uint32_t val) {
	if (r->used >= r->alloc) {
		void *tmp = realloc(r->buf, r->alloc * 2 * 4);
		if (!tmp) die("no mem");
		r->buf = tmp; r->alloc *= 2;
	}
	r->buf[r->used++] = val;
}
static int cmp_item32(const void *a, const void *b) { return memcmp(a, b, 4); }
static inline void result32_sort(const struct Result32 *r) {
	qsort(r->buf, r->used, 4, cmp_item32);
}
static inline bool result32_check(const struct Result32 *r, uint32_t val)
{
	unsigned i;
	if (r->used < MIN_BSEARCH) {
		for (i = 0; i < r->used; i++) {
			if (r->buf[i] == val)
				return true;
		}
		return false;
	}
	return bsearch(&val, r->buf, r->used, 4, cmp_item32) != NULL;
}
static inline void result32_free(struct Result32 *r) {
	free(r->buf);
	free(r);
}

#define DEF_FULL_RESULT(bits) \
struct Result ## bits { \
	uint8_t *buf; \
	unsigned alloc; \
	unsigned used; \
}; \
static struct Result ## bits *new_result ## bits(void) { \
	struct Result ## bits *r = zmalloc(sizeof(struct Result ## bits)); \
	r->buf = zmalloc(256 * bits / 8); \
	r->alloc = 256; \
	return r; \
} \
static void result ## bits ## _add(struct Result ## bits *r, const void *item) { \
	if (r->used >= r->alloc) { \
		void *tmp = realloc(r->buf, r->alloc * 2 * (bits / 8)); \
		if (!tmp) die("no mem"); \
		r->buf = tmp; r->alloc *= 2; \
	} \
	memcpy(r->buf + (bits/8) * r->used++, item, bits / 8); \
} \
static int cmp_item ## bits(const void *a, const void *b) { return memcmp(a, b, bits / 8); } \
static void result ## bits ## _sort(const struct Result ## bits *r) { \
	if (r->used > 0) \
	qsort(r->buf, r->used, bits / 8, cmp_item ## bits); \
} \
static inline bool result ## bits ## _check(const struct Result ## bits *r, const void *item) { \
	const uint8_t *p = r->buf; int n = r->used; \
	if (n < MIN_BSEARCH) { \
		while (n-- > 0) { \
			if (cmp_item ## bits(item, p) == 0) return true; \
			p += bits / 8; \
		} \
		return false; \
	} else { \
		return bsearch(item, r->buf, r->used, bits / 8, cmp_item ## bits) ? true : false; \
	} \
} \
static inline void result ## bits ## _free(struct Result ## bits *r) { \
	free(r->buf); free(r); \
}


