#include "client.h"
#include "pthread_wrapper.h"
#include "registry.h"

static struct _osdg_connection *connections = NULL;
static int connection_id = 0;
static pthread_mutex_t lock;

/* Static initialization is impossible on Windows, so we have this function */
void registry_init(void)
{
    pthread_mutex_init(&lock, NULL);
}

void registry_add_connection(struct _osdg_connection *conn)
{
    pthread_mutex_lock(&lock);
    conn->uid = connection_id++;
    HASH_ADD_INT(connections, uid, conn);
    pthread_mutex_unlock(&lock);
}

void registry_remove_connection(struct _osdg_connection *conn)
{
    if (conn->uid == -1)
        return;

    pthread_mutex_lock(&lock);
    HASH_DEL(connections, conn);
    pthread_mutex_unlock(&lock);

    conn->uid = -1;
}

struct _osdg_connection *registry_find_connection(int uid)
{
    struct _osdg_connection *conn;

    pthread_mutex_lock(&lock);
    HASH_FIND_INT(connections, &uid, conn);
    pthread_mutex_unlock(&lock);

    return conn;
}
