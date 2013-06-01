/*
 *  sql.c		rlm_sql - FreeRADIUS SQL Module
 *		Main code directly taken from ICRADIUS
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2001,2006  The FreeRADIUS server project
 * Copyright 2000  Mike Machado <mike@innercite.com>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2001  Chad Miller <cmiller@surfsouth.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>

#include	<sys/file.h>
#include	<sys/stat.h>

#include	<ctype.h>

#include	"rlm_sql.h"

#ifdef HAVE_PTHREAD_H
#endif


static void *sql_conn_create(void *ctx)
{
	int rcode;
	rlm_sql_t *inst = ctx;
	rlm_sql_handle_t *handle;

	handle = rad_calloc(sizeof(*handle));

	rcode = (inst->module->sql_init_socket)(handle, inst->config);
	if (rcode == 0) {
	  exec_trigger(NULL, inst->cs, "modules.sql.open", FALSE);
		return handle;
	}

	exec_trigger(NULL, inst->cs, "modules.sql.fail", TRUE);

	free(handle);
	return NULL;
}


static int sql_conn_delete(void *ctx, void *connection)
{
	rlm_sql_t *inst = ctx;
	rlm_sql_handle_t *handle = connection;

	exec_trigger(NULL, inst->cs, "modules.sql.close", FALSE);

	if (handle->conn) {
		(inst->module->sql_close)(handle, inst->config);
	}
	if (inst->module->sql_destroy_socket) {
		(inst->module->sql_destroy_socket)(handle, inst->config);
	}
	free(handle);

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_init_socketpool
 *
 *	Purpose: Connect to the sql server, if possible
 *
 *************************************************************************/
int sql_init_socketpool(rlm_sql_t * inst)
{
	inst->pool = fr_connection_pool_init(inst->cs, inst,
					     sql_conn_create,
					     NULL,
					     sql_conn_delete);
	if (!inst->pool) return -1;

	return 1;
}

/*************************************************************************
 *
 *     Function: sql_poolfree
 *
 *     Purpose: Clean up and free sql pool
 *
 *************************************************************************/
void sql_poolfree(rlm_sql_t * inst)
{
	fr_connection_pool_delete(inst->pool);
}


/*************************************************************************
 *
 *	Function: sql_get_socket
 *
 *	Purpose: Return a SQL handle from the connection pool
 *
 *************************************************************************/
rlm_sql_handle_t * sql_get_socket(rlm_sql_t * inst)
{
	return fr_connection_get(inst->pool);
}

/*************************************************************************
 *
 *	Function: sql_release_socket
 *
 *	Purpose: Frees a SQL handle back to the connection pool
 *
 *************************************************************************/
int sql_release_socket(rlm_sql_t * inst, rlm_sql_handle_t * handle)
{
	fr_connection_release(inst->pool, handle);
	return 0;
}


/*************************************************************************
 *
 *	Function: sql_userparse
 *
 *	Purpose: Read entries from the database and fill VALUE_PAIR structures
 *
 *************************************************************************/
int sql_userparse(VALUE_PAIR **head, rlm_sql_row_t row)
{
	VALUE_PAIR *vp;
	const char *ptr, *value;
	char buf[MAX_STRING_LEN];
	char do_xlat = 0;
	FR_TOKEN token, operator = T_EOL;

	/*
	 *	Verify the 'Attribute' field
	 */
	if (row[2] == NULL || row[2][0] == '\0') {
		radlog(L_ERR, "rlm_sql: The 'Attribute' field is empty or NULL, skipping the entire row.");
		return -1;
	}

	/*
	 *	Verify the 'op' field
	 */
	if (row[4] != NULL && row[4][0] != '\0') {
		ptr = row[4];
		operator = gettoken(&ptr, buf, sizeof(buf));
		if ((operator < T_OP_ADD) ||
		    (operator > T_OP_CMP_EQ)) {
			radlog(L_ERR, "rlm_sql: Invalid operator \"%s\" for attribute %s", row[4], row[2]);
			return -1;
		}

	} else {
		/*
		 *  Complain about empty or invalid 'op' field
		 */
		operator = T_OP_CMP_EQ;
		radlog(L_ERR, "rlm_sql: The 'op' field for attribute '%s = %s' is NULL, or non-existent.", row[2], row[3]);
		radlog(L_ERR, "rlm_sql: You MUST FIX THIS if you want the configuration to behave as you expect.");
	}

	/*
	 *	The 'Value' field may be empty or NULL
	 */
	value = row[3];
	/*
	 *	If we have a new-style quoted string, where the
	 *	*entire* string is quoted, do xlat's.
	 */
	if (row[3] != NULL &&
	   ((row[3][0] == '\'') || (row[3][0] == '`') || (row[3][0] == '"')) &&
	   (row[3][0] == row[3][strlen(row[3])-1])) {

		token = gettoken(&value, buf, sizeof(buf));
		switch (token) {
			/*
			 *	Take the unquoted string.
			 */
		case T_SINGLE_QUOTED_STRING:
		case T_DOUBLE_QUOTED_STRING:
			value = buf;
			break;

			/*
			 *	Mark the pair to be allocated later.
			 */
		case T_BACK_QUOTED_STRING:
			value = NULL;
			do_xlat = 1;
			break;

			/*
			 *	Keep the original string.
			 */
		default:
			value = row[3];
			break;
		}
	}

	/*
	 *	Create the pair
	 */
	vp = pairmake(row[2], NULL, operator);
	if (!vp) {
		radlog(L_ERR, "rlm_sql: Failed to create the pair: %s",
		       fr_strerror());
		return -1;
	}
	
	if (do_xlat) {
		if (pairmark_xlat(vp, value) < 0) {
			radlog(L_ERR, "rlm_sql: Error marking pair for xlat");
			
			pairbasicfree(vp);
			return -1;
		}
	} else {
		if (pairparsevalue(vp, value) < 0) {
			radlog(L_ERR, "rlm_sql: Error parsing value");
			
			pairbasicfree(vp);
			return -1;
		}
	}

	/*
	 *	Add the pair into the packet
	 */
	pairadd(head, vp);
	return 0;
}


/*************************************************************************
 *
 *	Function: rlm_sql_fetch_row
 *
 *	Purpose: call the module's sql_fetch_row and implement re-connect
 *
 *************************************************************************/
int rlm_sql_fetch_row(rlm_sql_handle_t **handle, rlm_sql_t *inst)
{
	int ret;

	if (!*handle || !(*handle)->conn) {
		return -1;
	}
	
	/* 
	 * We can't implement reconnect logic here, because the caller may require
	 * the original connection to free up queries or result sets associated with
	 * that connection.
	 */
	ret = (inst->module->sql_fetch_row)(*handle, inst->config);
	
	if (ret < 0) {
		radlog(L_ERR, "rlm_sql (%s): Error fetching row: %s", inst->config->xlat_name,
			   (inst->module->sql_error)(*handle, inst->config));
	}

	return ret;
}

/*************************************************************************
 *
 *	Function: rlm_sql_query
 *
 *	Purpose: call the module's sql_query and implement re-connect
 *
 *************************************************************************/
int rlm_sql_query(rlm_sql_handle_t **handle, rlm_sql_t *inst, char *query)
{
	int ret;

	/*
	 *	If there's no query, return an error.
	 */
	if (!query || !*query) {
		return -1;
	}

	if (!*handle || !(*handle)->conn) {
		ret = -1;
		goto sql_down;
	}
	
	while (1) {
		DEBUG("rlm_sql (%s): Executing query: '%s'",
		      inst->config->xlat_name, query);

		ret = (inst->module->sql_query)(*handle, inst->config, query);
		/*
		 * Run through all available sockets until we exhaust all existing
		 * sockets in the pool and fail to establish a *new* connection.
		 */
		if (ret == SQL_DOWN) {
			sql_down:
			*handle = fr_connection_reconnect(inst->pool, *handle);
			if (!*handle) return SQL_DOWN;
			
			continue;
		}
		
		if (ret < 0) {
			radlog(L_ERR,
				   "rlm_sql (%s): Database query error: '%s'",
				   inst->config->xlat_name,
				   (inst->module->sql_error)(*handle, inst->config));
		}
		
		return ret;
	}
}

/*************************************************************************
 *
 *	Function: rlm_sql_select_query
 *
 *	Purpose: call the module's sql_select_query and implement re-connect
 *
 *************************************************************************/
int rlm_sql_select_query(rlm_sql_handle_t **handle, rlm_sql_t *inst, char *query)
{
	int ret;

	/*
	 *	If there's no query, return an error.
	 */
	if (!query || !*query) {
		return -1;
	}

	if (!*handle || !(*handle)->conn) {
		ret = -1;
		goto sql_down;
	}
	
	while (1) {
		DEBUG("rlm_sql (%s): Executing query: '%s'",
		      inst->config->xlat_name, query);

		ret = (inst->module->sql_select_query)(*handle, inst->config, query);
		/*
		 * Run through all available sockets until we exhaust all existing
		 * sockets in the pool and fail to establish a *new* connection.
		 */
		if (ret == SQL_DOWN) {
			sql_down:
			*handle = fr_connection_reconnect(inst->pool, *handle);
			if (!*handle) return SQL_DOWN;
			
			continue;
		}
		
		if (ret < 0) {
			radlog(L_ERR,
				   "rlm_sql (%s): Database query error '%s'",
				   inst->config->xlat_name,
				   (inst->module->sql_error)(*handle, inst->config));
		}
		
		return ret;
	}
}


/*************************************************************************
 *
 *	Function: sql_getvpdata
 *
 *	Purpose: Get any group check or reply pairs
 *
 *************************************************************************/
int sql_getvpdata(rlm_sql_t * inst, rlm_sql_handle_t **handle, VALUE_PAIR **pair, char *query)
{
	rlm_sql_row_t row;
	int     rows = 0;

	if (rlm_sql_select_query(handle, inst, query)) {
		return -1;
	}

	while (rlm_sql_fetch_row(handle, inst) == 0) {
		row = (*handle)->row;
		if (!row)
			break;
		if (sql_userparse(pair, row) != 0) {
			radlog(L_ERR, "rlm_sql (%s): Error getting data from database", inst->config->xlat_name);
			
			(inst->module->sql_finish_select_query)(*handle, inst->config);
			
			return -1;
		}
		rows++;
	}
	(inst->module->sql_finish_select_query)(*handle, inst->config);

	return rows;
}

/*
 *	Log the query to a file.
 */
void rlm_sql_query_log(rlm_sql_t *inst, REQUEST *request,
		       sql_acct_section_t *section, char *query)
{
	int fd;
	const char *filename = NULL;
	char buffer[8192];

	if (section) filename = section->logfile;

	if (!filename) filename = inst->config->logfile;

	if (!filename) return;

	if (!radius_xlat(buffer, sizeof(buffer), filename, request, NULL, NULL)) {
		radlog(L_ERR, "rlm_sql (%s): xlat failed.",
		       inst->config->xlat_name);
		return;
	}

	fd = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0666);
	if (fd < 0) {
		radlog(L_ERR, "rlm_sql (%s): Couldn't open logfile '%s': %s",
		       inst->config->xlat_name, buffer, strerror(errno));
		return;
	}

	if ((rad_lockfd(fd, MAX_QUERY_LEN) < 0) ||
	    (write(fd, query, strlen(query)) < 0) ||
	    (write(fd, ";\n", 2) < 0)) {
		radlog(L_ERR, "rlm_sql (%s): Failed writing to logfile '%s': %s",
		       inst->config->xlat_name, buffer, strerror(errno));
	}
	close(fd);		/* and release the lock */
}
