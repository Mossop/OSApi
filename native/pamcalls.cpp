#include <dlfcn.h>
#include <security/pam_appl.h>

#define PAM_LIBRARY "libpam.so"

void *libpam = NULL;

int open_pam()
{
	libpam = dlopen(PAM_LIBRARY, RTLD_NOW|RTLD_GLOBAL);
	if (libpam==NULL)
	{
		return 0;
	}
	return 1;
}

void close_pam()
{
	if (libpam!=NULL)
		dlclose(libpam);
}

/* -------------- The Linux-PAM Framework layer API ------------- */

int call_pam_start(const char *service_name, const char *user,
                     const struct pam_conv *pam_conversation,
                     pam_handle_t **pamh)
{
	char *error;
	int (*call_ptr)(const char*, const char*, const struct pam_conv*, pam_handle_t**);

	call_ptr = (int(*)(const char*, const char*, const struct pam_conv*, pam_handle_t**))
		dlsym(libpam,"pam_start");
	if ((error = dlerror())!=NULL)
	{
		//fprintf(stderr,"Error locating symbol: %s\n",error);
		return PAM_SYMBOL_ERR;
	}
	return (*call_ptr)(service_name, user, pam_conversation, pamh);
}

int call_pam_end(pam_handle_t *pamh, int pam_status)
{
	char *error;
	int (*call_ptr)(pam_handle_t*, int);
	
	call_ptr = (int(*)(pam_handle_t*, int))
		dlsym(libpam,"pam_end");
	if ((error = dlerror())!=NULL)
	{
		//fprintf(stderr,"Error locating symbol: %s\n",error);
		return PAM_SYMBOL_ERR;
	}
	return (*call_ptr)(pamh, pam_status);
}

/* Authentication API's */

int call_pam_authenticate(pam_handle_t *pamh, int flags)
{
	char *error;
	int (*call_ptr)(pam_handle_t*, int);
	
	call_ptr = (int(*)(pam_handle_t*, int))
		dlsym(libpam,"pam_authenticate");
	if ((error = dlerror())!=NULL)
	{
		//fprintf(stderr,"Error locating symbol: %s\n",error);
		return PAM_SYMBOL_ERR;
	}
	return (*call_ptr)(pamh, flags);
}

int call_pam_setcred(pam_handle_t *pamh, int flags)
{
	char *error;
	int (*call_ptr)(pam_handle_t*, int);
	
	call_ptr = (int(*)(pam_handle_t*, int))
		dlsym(libpam,"pam_setcred");
	if ((error = dlerror())!=NULL)
	{
		//fprintf(stderr,"Error locating symbol: %s\n",error);
		return PAM_SYMBOL_ERR;
	}
	return (*call_ptr)(pamh, flags);
}

/* Account Management API's */

int call_pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
	char *error;
	int (*call_ptr)(pam_handle_t*, int);
	
	call_ptr = (int(*)(pam_handle_t*, int))
		dlsym(libpam,"pam_acct_mgmt");
	if ((error = dlerror())!=NULL)
	{
		//fprintf(stderr,"Error locating symbol: %s\n",error);
		return PAM_SYMBOL_ERR;
	}
	return (*call_ptr)(pamh, flags);
}

/* Session Management API's */

int call_pam_open_session(pam_handle_t *pamh, int flags)
{
	char *error;
	int (*call_ptr)(pam_handle_t*, int);
	
	call_ptr = (int(*)(pam_handle_t*, int))
		dlsym(libpam,"pam_open_session");
	if ((error = dlerror())!=NULL)
	{
		//fprintf(stderr,"Error locating symbol: %s\n",error);
		return PAM_SYMBOL_ERR;
	}
	return (*call_ptr)(pamh, flags);
}

int call_pam_close_session(pam_handle_t *pamh, int flags)
{
	char *error;
	int (*call_ptr)(pam_handle_t*, int);
	
	call_ptr = (int(*)(pam_handle_t*, int))
		dlsym(libpam,"pam_close_session");
	if ((error = dlerror())!=NULL)
	{
		//fprintf(stderr,"Error locating symbol: %s\n",error);
		return PAM_SYMBOL_ERR;
	}
	return (*call_ptr)(pamh, flags);
}

/* Password Management API's */

int call_pam_chauthtok(pam_handle_t *pamh, int flags)
{
	char *error;
	int (*call_ptr)(pam_handle_t*, int);
	
	call_ptr = (int(*)(pam_handle_t*, int))
		dlsym(libpam,"pam_chauthtok");
	if ((error = dlerror())!=NULL)
	{
		//fprintf(stderr,"Error locating symbol: %s\n",error);
		return PAM_SYMBOL_ERR;
	}
	return (*call_ptr)(pamh, flags);
}

const char *call_pam_strerror(pam_handle_t *pamh, int errnum)
{
	char *error;
	const char* (*call_ptr)(pam_handle_t*, int);
	
	call_ptr = (const char* (*)(pam_handle_t*, int))
		dlsym(libpam,"pam_strerror");
	if ((error = dlerror())!=NULL)
	{
		//fprintf(stderr,"Error locating symbol: %s\n",error);
		return "";
	}
	return (*call_ptr)(pamh, errnum);
}
