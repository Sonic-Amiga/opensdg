#ifndef INTERNAL_MAINLOOP_H
#define INTERNAL_MAINLOOP_H

int register_connection(struct _osdg_client *conn);
void unregister_connection(struct _osdg_client *conn);

#endif