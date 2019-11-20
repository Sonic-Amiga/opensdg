#ifndef INTERNAL_MAINLOOP_H
#define INTERNAL_MAINLOOP_H

struct client_req;

void mainloop_events_init(void);
void mainloop_events_shutdown(void);
void mainloop_send_client_request(struct client_req *req);
void mainloop_handle_client_requests(void);

int mainloop_init(void);
void mainloop_shutdown(void);
void mainloop_client_event(void);
int mainloop_add_connection(struct _osdg_connection *conn);
void mainloop_remove_connection(struct _osdg_connection *conn);

#endif
