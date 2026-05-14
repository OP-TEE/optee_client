/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Linaro Limited
 */

#ifndef LIBCKTEEC_LOCAL_UTILS_H
#define LIBCKTEEC_LOCAL_UTILS_H

#define ARRAY_SIZE(array)	(sizeof(array) / sizeof(array[0]))

#define COMPILE_TIME_ASSERT(x) \
	do { \
		switch (0) { case 0: case ((x) ? 1: 0) : default : break; } \
	} while (0)

/*
 * Checking overflow for addition, subtraction and multiplication. Result
 * of operation is stored in res which is a pointer to some kind of
 * integer.
 *
 * The macros return true if an overflow occurred and *res is undefined.
 */
#define ADD_OVERFLOW(a, b, res) __compiler_add_overflow((a), (b), (res))
#define SUB_OVERFLOW(a, b, res) __compiler_sub_overflow((a), (b), (res))
#define MUL_OVERFLOW(a, b, res) __compiler_mul_overflow((a), (b), (res))

#define __GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + \
		       __GNUC_PATCHLEVEL__)

#if __GCC_VERSION >= 50100 && !defined(__CHECKER__)
#define __HAVE_BUILTIN_OVERFLOW 1
#endif

#if __GCC_VERSION >= 90100 && !defined(__CHECKER__)
#define __HAVE_SINGLE_ARGUMENT_STATIC_ASSERT 1
#endif

#ifdef __HAVE_BUILTIN_OVERFLOW
#define __compiler_add_overflow(a, b, res) \
	__builtin_add_overflow((a), (b), (res))

#define __compiler_sub_overflow(a, b, res) \
	__builtin_sub_overflow((a), (b), (res))

#define __compiler_mul_overflow(a, b, res) \
	__builtin_mul_overflow((a), (b), (res))
#else /*!__HAVE_BUILTIN_OVERFLOW*/

/*
 * Copied/inspired from https://www.fefe.de/intof.html
 */

#define __INTOF_ASSIGN(dest, src) (__extension__({ \
	typeof(src) __intof_x = (src); \
	typeof(dest) __intof_y = __intof_x; \
	(((uintmax_t)__intof_x == (uintmax_t)__intof_y) && \
	 ((__intof_x < 1) == (__intof_y < 1)) ? \
		(void)((dest) = __intof_y) , 0 : 1); \
}))

#define __INTOF_ADD(c, a, b) (__extension__({ \
	typeof(a) __intofa_a = (a); \
	typeof(b) __intofa_b = (b); \
	intmax_t __intofa_a_signed = __intofa_a; \
	uintmax_t __intofa_a_unsigned = __intofa_a; \
	intmax_t __intofa_b_signed = __intofa_b; \
	uintmax_t __intofa_b_unsigned = __intofa_b; \
	\
	__intofa_b < 1 ? \
		__intofa_a < 1 ? \
			((INTMAX_MIN - __intofa_b_signed <= \
			  __intofa_a_signed)) ? \
				__INTOF_ASSIGN((c), __intofa_a_signed + \
						    __intofa_b_signed) : 1 \
		: \
			((__intofa_a_unsigned >= (uintmax_t)-__intofa_b) ? \
				__INTOF_ASSIGN((c), __intofa_a_unsigned + \
						    __intofa_b_signed) \
			: \
				__INTOF_ASSIGN((c), \
					(intmax_t)(__intofa_a_unsigned + \
						   __intofa_b_signed))) \
	: \
		__intofa_a < 1 ? \
			((__intofa_b_unsigned >= (uintmax_t)-__intofa_a) ? \
				__INTOF_ASSIGN((c), __intofa_a_signed + \
						    __intofa_b_unsigned) \
			: \
				__INTOF_ASSIGN((c), \
					(intmax_t)(__intofa_a_signed + \
						   __intofa_b_unsigned))) \
		: \
			((UINTMAX_MAX - __intofa_b_unsigned >= \
			  __intofa_a_unsigned) ? \
				__INTOF_ASSIGN((c), __intofa_a_unsigned + \
						    __intofa_b_unsigned) : 1); \
}))

#define __INTOF_SUB(c, a, b) (__extension__({ \
	typeof(a) __intofs_a = a; \
	typeof(b) __intofs_b = b; \
	intmax_t __intofs_a_signed = __intofs_a; \
	uintmax_t __intofs_a_unsigned = __intofs_a; \
	intmax_t __intofs_b_signed = __intofs_b; \
	uintmax_t __intofs_b_unsigned = __intofs_b; \
	\
	__intofs_b < 1 ? \
		__intofs_a < 1 ? \
			((INTMAX_MAX + __intofs_b_signed >= \
			  __intofs_a_signed) ? \
				__INTOF_ASSIGN((c), __intofs_a_signed - \
						    __intofs_b_signed) : 1) \
		: \
			(((uintmax_t)(UINTMAX_MAX + __intofs_b_signed) >= \
			  __intofs_a_unsigned) ? \
				__INTOF_ASSIGN((c), __intofs_a - \
						    __intofs_b) : 1) \
	: \
		__intofs_a < 1 ? \
			(((intmax_t)(INTMAX_MIN + __intofs_b) <= \
			  __intofs_a_signed) ? \
				__INTOF_ASSIGN((c), \
					(intmax_t)(__intofs_a_signed - \
						   __intofs_b_unsigned)) : 1) \
		: \
			((__intofs_b_unsigned <= __intofs_a_unsigned) ? \
				__INTOF_ASSIGN((c), __intofs_a_unsigned - \
						    __intofs_b_unsigned) \
			: \
				__INTOF_ASSIGN((c), \
					(intmax_t)(__intofs_a_unsigned - \
						   __intofs_b_unsigned))); \
}))

/*
 * Dealing with detecting overflow in multiplication of integers.
 *
 * First step is to remove two corner cases with the minum signed integer
 * which can't be represented as a positive integer + sign.
 * Multiply with 0 or 1 can't overflow, no checking needed of the operation,
 * only if it can be assigned to the result.
 *
 * After the corner cases are eliminated we convert the two factors to
 * positive unsigned values, keeping track of the original in another
 * variable which is used at the end to determine the sign of the product.
 *
 * The two terms (a and b) are divided into upper and lower half (x1 upper
 * and x0 lower), so the product is:
 * ((a1 << hshift) + a0) * ((b1 << hshift) + b0)
 * which also is:
 * ((a1 * b1) << (hshift * 2)) +				(T1)
 * ((a1 * b0 + a0 * b1) << hshift) +				(T2)
 * (a0 * b0)							(T3)
 *
 * From this we can tell and (a1 * b1) has to be 0 or we'll overflow, that
 * is, at least one of a1 or b1 has to be 0. Once this has been checked the
 * addition: ((a1 * b0) << hshift) + ((a0 * b1) << hshift)
 * isn't an addition as one of the terms will be 0.
 *
 * Since each factor in: (a0 * b0)
 * only uses half the capicity of the underlaying type it can't overflow
 *
 * The addition of T2 and T3 can overflow so we use __INTOF_ADD() to
 * perform that addition. If the addition succeeds without overflow the
 * result is assigned the required sign and checked for overflow again.
 */

#define __intof_mul_negate	((__intof_oa < 1) != (__intof_ob < 1))
#define __intof_mul_hshift	(sizeof(uintmax_t) * 8 / 2)
#define __intof_mul_hmask	(UINTMAX_MAX >> __intof_mul_hshift)
#define __intof_mul_a0		((uintmax_t)(__intof_a) >> __intof_mul_hshift)
#define __intof_mul_b0		((uintmax_t)(__intof_b) >> __intof_mul_hshift)
#define __intof_mul_a1		((uintmax_t)(__intof_a) & __intof_mul_hmask)
#define __intof_mul_b1		((uintmax_t)(__intof_b) & __intof_mul_hmask)
#define __intof_mul_t		(__intof_mul_a1 * __intof_mul_b0 + \
				 __intof_mul_a0 * __intof_mul_b1)

#define __INTOF_MUL(c, a, b) (__extension__({ \
	typeof(a) __intof_oa = (a); \
	typeof(a) __intof_a = __intof_oa < 1 ? -__intof_oa : __intof_oa; \
	typeof(b) __intof_ob = (b); \
	typeof(b) __intof_b = __intof_ob < 1 ? -__intof_ob : __intof_ob; \
	typeof(c) __intof_c; \
	\
	__intof_oa == 0 || __intof_ob == 0 || \
	__intof_oa == 1 || __intof_ob == 1 ? \
		__INTOF_ASSIGN((c), __intof_oa * __intof_ob) : \
	(__intof_mul_a0 && __intof_mul_b0) || \
	 __intof_mul_t > __intof_mul_hmask ?  1 : \
	__INTOF_ADD((__intof_c), __intof_mul_t << __intof_mul_hshift, \
				 __intof_mul_a1 * __intof_mul_b1) ? 1 : \
	__intof_mul_negate ? __INTOF_ASSIGN((c), -__intof_c) : \
			     __INTOF_ASSIGN((c), __intof_c); \
}))

#define __compiler_add_overflow(a, b, res) __INTOF_ADD(*(res), (a), (b))
#define __compiler_sub_overflow(a, b, res) __INTOF_SUB(*(res), (a), (b))
#define __compiler_mul_overflow(a, b, res) __INTOF_MUL(*(res), (a), (b))

#endif /*!__HAVE_BUILTIN_OVERFLOW*/

#endif /*LIBCKTEEC_LOCAL_UTILS_H*/
