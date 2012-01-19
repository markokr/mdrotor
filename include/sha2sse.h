
/*
 * Common SHA2 code for SSE2
 */

/* CH: (x & y) ^ ((~x) & z) */
#define CH(x,y,z) XOR(AND(x, y), ANDNOT(x, z))

/* MAJ: (x & y) ^ (x & z) ^ (y & z) */
#define MAJ(x,y,z)  XOR(AND(x,y), XOR(AND(x,z), AND(y,z)))

/* E: ror(x, s1) ^ ror(x, s2) ^ ror(x, s3) */
#define E_base(x, s1, s2, s3) XOR(ROR(x, s1), XOR(ROR(x, s2), ROR(x, s3)))

/* O: ror(x, s1) ^ ror(x, s2) ^ (x >> s3) */
#define O_base(x, s1, s2, s3) XOR(ROR(x, s1), XOR(ROR(x, s2), SHR(x, s3)))

#define E_0(x) E_base(x, E0S1, E0S2, E0S3)
#define E_1(x) E_base(x, E1S1, E1S2, E1S3)
#define O_0(x) O_base(x, O0S1, O0S2, O0S3)
#define O_1(x) O_base(x, O1S1, O1S2, O1S3)

#define W(n)		sval_load(&buf[n])
#define setW(n, v)	sval_store(&buf[n], v)

#define COPY(t) setW(t, sval_load(&ctx->buf[t]))

/* W(t) = O_1(W(t - 2)) + W(t - 7) + O_0(W(t - 15)) + W(t - 16); */
#define PREPARE(t) setW(t, ADD(ADD(O_1(W(t - 2)), W(t - 7)), \
			       ADD(O_0(W(t - 15)), W(t - 16))))

/* tmp1 = h + E_1(e) + CH(e,f,g) + k[t] + W(t); */
/* tmp2 = E_0(a) + MAJ(a,b,c); */
/* h = g; g = f; f = e; e = d + tmp1; d = c; c = b; b = a; a = tmp1 + tmp2; */
#define SHA2ROUND(t) do { \
	__m128i v1, v2; \
	v1 = ADD(ADD(CH(e,f,g), E_1(e)), \
		 ADD(ADD(sval_load(&K[t]), h), W(t))); \
	h = g; g = f; f = e; \
	e = ADD(d, v1); \
	v2 = ADD(MAJ(a, b, c), E_0(a)); \
	d = c; c = b; b = a; \
	a = ADD(v1, v2); \
} while (0)

#define FINAL(idx, val) \
	sval_store(&ctx->final[idx], ADD(val, sval_load(&iv[idx])))

