/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#ifndef TEE_DEFERRED_WORK_H
#define TEE_DEFERRED_WORK_H

/*
 * Create thread to trigger deferred works in OP-TEE.
 *
 * The thread will terminate after all deferred works
 * will be done.
 */
int tee_dw_poller_start(void);

#endif
