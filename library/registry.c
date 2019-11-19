#include "client.h"
#include "registry.h"

static struct _osdg_connection *connections = NULL;
static int connection_id = 0;

void registry_add_connection(struct _osdg_connection *conn)
{
    conn->uid = connection_id++;
    HASH_ADD_INT(connections, uid, conn);
}

void registry_remove_connection(struct _osdg_connection *conn)
{
    if (conn->uid == -1)
        return;

    HASH_DEL(connections, conn);
    conn->uid = -1;
}

struct _osdg_connection *registry_find_connection(int uid)
{
    struct _osdg_connection *conn;

    HASH_FIND_INT(connections, &uid, conn);
    return conn;
}
