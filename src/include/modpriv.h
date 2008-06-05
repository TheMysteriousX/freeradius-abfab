/* modpriv.h: Stuff needed by both modules.c and modcall.c, but should not be
 * accessed from anywhere else.
 *
 * Version: $Id$ */
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#ifndef WITHOUT_LIBLTDL
#include "ltdl.h"
#else
typedef void *lt_dlhandle;

lt_dlhandle lt_dlopenext(const char *name);
void *lt_dlsym(lt_dlhandle handle, const char *symbol);

#define LTDL_SET_PRELOADED_SYMBOLS(_x)
#define lt_dlinit(_x) (0)
#define lt_dlclose(_x)
#define lt_dlexit(_x)
#define lt_dlerror(foo) "Internal error"
#define lt_dlsetsearchpath(_x)
#endif

/*
 *	Keep track of which modules we've loaded.
 */
typedef struct module_entry_t {
	char			name[MAX_STRING_LEN];
	const module_t		*module;
	lt_dlhandle		handle;
} module_entry_t;

/*
 *	Per-instance data structure, to correlate the modules
 *	with the instance names (may NOT be the module names!),
 *	and the per-instance data structures.
 */
typedef struct module_instance_t {
	char			name[MAX_STRING_LEN];
	module_entry_t		*entry;
	void                    *insthandle;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		*mutex;
#endif
	void			*old_insthandle[16];
} module_instance_t;

module_instance_t *find_module_instance(CONF_SECTION *, const char *instname);
