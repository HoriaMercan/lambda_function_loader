/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdlib.h>


/* Useful macro for handling error codes. */
#define DIE(assertion, call_description)			\
	do {							\
		if (assertion) {				\
			fprintf(stderr, "(%s, %s, %d): ",	\
				__FILE__, __func__, __LINE__);	\
			perror(call_description);		\
			exit(EXIT_FAILURE);			\
		}						\
	} while (0)

#endif /* _UTILS_H */