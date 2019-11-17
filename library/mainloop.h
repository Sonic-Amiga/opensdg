#ifndef INTERNAL_MAINLOOP_H
#define INTERNAL_MAINLOOP_H

int mainloop_init(void);
void mainloop_shutdown(void);
void mainloop_send_client_request(struct client_req *req);
int mainloop_add_connection(struct _osdg_connection *conn);
void mainloop_remove_connection(struct _osdg_connection *conn);

#endif