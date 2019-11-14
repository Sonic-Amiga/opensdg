#ifndef INTERNAL_REGISTRY_H
#define INTERNAL_REGISTRY_H

void registry_init(void);
void registry_add_connection(struct _osdg_client *conn);
void registry_remove_connection(struct _osdg_client *conn);
struct _osdg_client *registry_find_connection(int uid);

#endif
