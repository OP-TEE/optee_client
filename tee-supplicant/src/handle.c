/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdlib.h>
#include <string.h>
#include "handle.h"

/*
 * Define the initial capacity of the database. It should be a low number
 * multiple of 2 since some databases a likely to only use a few handles.
 * Since the algorithm is to doubles up when growing it shouldn't cause a
 * noticable overhead on large databases.
 */
#define HANDLE_DB_INITIAL_MAX_PTRS	4

static void mutex_lock(struct handle_db *db)
{
	if (db->mu)
		pthread_mutex_lock(db->mu);
}

static void mutex_unlock(struct handle_db *db)
{
	if (db->mu)
		pthread_mutex_unlock(db->mu);
}


void handle_db_set_mutex(struct handle_db *db, pthread_mutex_t *mu)
{
	db->mu = mu;
}

void handle_db_destroy(struct handle_db *db)
{
	if (db) {
		mutex_lock(db);
		free(db->ptrs);
		db->ptrs = NULL;
		db->max_ptrs = 0;
		mutex_unlock(db);
	}
}

int handle_get(struct handle_db *db, void *ptr)
{
	size_t n;
	void *p;
	size_t new_max_ptrs;
	int ret;

	if (!db || !ptr)
		return -1;

	mutex_lock(db);

	/* Try to find an empty location */
	for (n = 0; n < db->max_ptrs; n++) {
		if (!db->ptrs[n]) {
			db->ptrs[n] = ptr;
			ret = n;
			goto out;
		}
	}

	/* No location available, grow the ptrs array */
	if (db->max_ptrs)
		new_max_ptrs = db->max_ptrs * 2;
	else
		new_max_ptrs = HANDLE_DB_INITIAL_MAX_PTRS;
	p = realloc(db->ptrs, new_max_ptrs * sizeof(void *));
	if (!p) {
		ret = -1;
		goto out;
	}
	db->ptrs = p;
	memset(db->ptrs + db->max_ptrs, 0,
	       (new_max_ptrs - db->max_ptrs) * sizeof(void *));
	db->max_ptrs = new_max_ptrs;

	/* Since n stopped at db->max_ptrs there is an empty location there */
	db->ptrs[n] = ptr;
	ret = n;

out:
	mutex_unlock(db);
	return ret;
}

void *handle_put(struct handle_db *db, int handle)
{
	void *p;

	if (!db || handle < 0)
		return NULL;

	mutex_lock(db);

	if ((size_t)handle >= db->max_ptrs) {
		p = NULL;
		goto out;
	}

	p = db->ptrs[handle];
	db->ptrs[handle] = NULL;

out:
	mutex_unlock(db);
	return p;
}

void *handle_lookup(struct handle_db *db, int handle)
{
	void *p;

	if (!db || handle < 0)
		return NULL;

	mutex_lock(db);

	if ((size_t)handle >= db->max_ptrs) {
		p = NULL;
		goto out;
	}

	p = db->ptrs[handle];

out:
	mutex_unlock(db);
	return p;
}
