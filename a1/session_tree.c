#include "RUSHBSvr.h"

void ST_insert(struct ST** st, uint16_t client_src_port, struct Session* session) {
	if (*st == NULL) {

		struct ST* tmp = (struct ST*)malloc(sizeof(struct ST));
		tmp->l = NULL;
		tmp->r = NULL;
		tmp->session = session;
		tmp->src_port = client_src_port;

		*st = tmp;
		return;
	}

	if (client_src_port > (*st)->src_port)
		ST_insert(&(*st)->r, client_src_port, session);
	else
		ST_insert(&(*st)->l, client_src_port, session);
}

struct ST* ST_delete(struct ST** st, uint16_t client_src_port) {
	if (*st == NULL)
		return ;
	if (client_src_port > (*st)->src_port)
		(*st)->r = ST_delete(&(*st)->r, client_src_port);
	else if (client_src_port < (*st)->src_port)
		(*st)->l = ST_delete(&(*st)->l, client_src_port);
	else {
		if ((*st)->l == NULL) {
			struct ST* tmp = (*st)->r;
			free(*st);
			return *st = tmp;
		}
		else if ((*st)->r == NULL) {
			struct ST* tmp = (*st)->l;
			free(*st);
			return *st = tmp;
		}
		struct ST* tmp = ((*st)->r->src_port > (*st)->l->src_port ? (*st)->l : (*st)->r);
		(*st)->src_port = tmp->src_port;
		(*st)->r = ST_delete(&(*st)->r, tmp->src_port);
	}
	return (*st);
}

struct Session* ST_search(struct ST* st, uint16_t client_src_port) {
	if (st == NULL)
		return NULL;
	if (client_src_port > st->src_port)
		ST_search(st->r, client_src_port);
	else if (client_src_port < st->src_port)
		ST_search(st->l, client_src_port);
	else //(client_src_port == st->src_port)
		return st->session;
	
}