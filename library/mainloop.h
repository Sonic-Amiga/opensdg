#ifndef INTERNAL_MAINLOOP_H
#define INTERNAL_MAINLOOP_H

int mainloop_add_connection(struct _osdg_client *conn);
void mainloop_remove_connection(struct _osdg_client *conn);

#endif