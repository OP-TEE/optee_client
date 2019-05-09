/* FIXME: Copyright */

#include <stdint.h>
#include <sys/queue.h>
#include <stdlib.h>

#include <handle.h>
#include <tee_service_handle.h>

/* TA is identified by this instance */
struct service_instance {
	uint32_t id;
	struct handle_db db;
	TAILQ_ENTRY(service_instance) link;
};

static pthread_mutex_t service_db_mutex = PTHREAD_MUTEX_INITIALIZER;
TAILQ_HEAD(, service_instance) service_instances =
					TAILQ_HEAD_INITIALIZER(service_instances);

static void service_db_lock(void)
{
	pthread_mutex_lock(&service_db_mutex);
}

static void service_db_unlock(void)
{
	pthread_mutex_unlock(&service_db_mutex);
}

static struct service_instance *service_instance_find(uint32_t instance_id)
{
	struct service_instance *instance;

	TAILQ_FOREACH(instance, &service_instances, link) {
		if (instance->id == instance_id)
			return instance;
	}
	return NULL;
}

int service_handle_new(uint32_t instance_id, void *ptr)
{
	int handle = -1;
	struct service_instance *instance;

	service_db_lock();

	instance = service_instance_find(instance_id);
	if (!instance) {
		instance = calloc(1, sizeof(*instance));
		if (!instance)
			goto out;
		instance->id = instance_id;
		TAILQ_INSERT_TAIL(&service_instances, instance, link);
	}

	handle = handle_get(&instance->db, ptr);

out:
	service_db_unlock();
	return handle;
}

void *service_handle_get(uint32_t instance_id, uint32_t handle)
{
	void *ptr = NULL;
	struct service_instance *instance;

	service_db_lock();
	instance = service_instance_find(instance_id);
	if (instance)
		ptr = handle_lookup(&instance->db, handle);
	service_db_unlock();
	return ptr;
}

void service_handle_put(uint32_t instance_id, uint32_t handle)
{
	struct service_instance *instance;

	service_db_lock();
	instance = service_instance_find(instance_id);
	if (instance)
		handle_put(&instance->db, handle);
	service_db_unlock();
}
