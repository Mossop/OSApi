package com.blueprintit.security.pam;

/**
 * @author Dave
 */
public class Pam
{
	/* ----------------- The Linux-PAM return values ------------------ */

	public static final int PAM_SUCCESS = 0;           			/* Successful function return */
	public static final int PAM_OPEN_ERR = 1;          			/* dlopen() failure when dynamically */
	                                												/* loading a service module */
	public static final int PAM_SYMBOL_ERR = 2;        			/* Symbol not found */
	public static final int PAM_SERVICE_ERR = 3;       			/* Error in service module */
	public static final int PAM_SYSTEM_ERR = 4;        			/* System error */
	public static final int PAM_BUF_ERR = 5;           			/* Memory buffer error */
	public static final int PAM_PERM_DENIED = 6;       			/* Permission denied */
	public static final int PAM_AUTH_ERR = 7;          			/* Authentication failure */
	public static final int PAM_CRED_INSUFFICIENT = 8; 			/* Can not access authentication data */
	                                												/* due to insufficient credentials */
	public static final int PAM_AUTHINFO_UNAVAIL = 9;  			/* Underlying authentication service */
	                                												/* can not retrieve authenticaiton */
	                                												/* information  */
	public static final int PAM_USER_UNKNOWN = 10;     			/* User not known to the underlying */
	                                												/* authenticaiton module */
	public static final int PAM_MAXTRIES = 11;         			/* An authentication service has */
	                                												/* maintained a retry count which has */
	                                												/* been reached.  No further retries */
	                                												/* should be attempted */
	public static final int PAM_NEW_AUTHTOK_REQD = 12; 			/* New authentication token required. */
	                                												/* This is normally returned if the */
	                                												/* machine security policies require */
	                                												/* that the password should be changed */
	                                												/* beccause the password is NULL or it */
	                                												/* has aged */
	public static final int PAM_ACCT_EXPIRED = 13;     			/* User account has expired */
	public static final int PAM_SESSION_ERR = 14;      			/* Can not make/remove an entry for */
	                                												/* the specified session */
	public static final int PAM_CRED_UNAVAIL = 15;     			/* Underlying authentication service */
	                                												/* can not retrieve user credentials */
	                                												/* unavailable */
	public static final int PAM_CRED_EXPIRED = 16;     			/* User credentials expired */
	public static final int PAM_CRED_ERR = 17;         			/* Failure setting user credentials */
	public static final int PAM_NO_MODULE_DATA = 18;   			/* No module specific data is present */
	public static final int PAM_CONV_ERR = 19;         			/* Conversation error */
	public static final int PAM_AUTHTOK_ERR = 20;      			/* Authentication token manipulation error */
	public static final int PAM_AUTHTOK_RECOVER_ERR = 21; 	/* Authentication information */
	                                   											/* cannot be recovered */
	public static final int PAM_AUTHTOK_LOCK_BUSY = 22;   	/* Authentication token lock busy */
	public static final int PAM_AUTHTOK_DISABLE_AGING = 23; /* Authentication token aging disabled */
	public static final int PAM_TRY_AGAIN = 24;        			/* Preliminary check by password service */
	public static final int PAM_IGNORE = 25;           			/* Ingore underlying account module */
	                                												/* regardless of whether the control */
	                                												/* flag is required, optional, or sufficient */
	public static final int PAM_ABORT = 26;            			/* Critical error (?module fail now request) */
	public static final int PAM_AUTHTOK_EXPIRED  = 27; 			/* user's authentication token has expired */
	public static final int PAM_MODULE_UNKNOWN   = 28; 			/* module is not known */

	public static final int PAM_BAD_ITEM         = 29; 			/* Bad item passed to pam_*_item() */
	public static final int PAM_CONV_AGAIN       = 30; 			/* conversation function is event driven
	                                     											and data is not available yet */
	public static final int PAM_INCOMPLETE       = 31; 			/* please call this function again to
	                                   												complete authentication stack. Before
	                                   												calling again, verify that conversation
	                                   												is completed */

	/* ---------------------- The Linux-PAM flags -------------------- */

	/* Authentication service should not generate any messages */
	public static final int PAM_SILENT                      =0x8000;

	/* Note: these flags are used by pam_authenticate{,_secondary}() */

	/* The authentication service should return PAM_AUTH_ERROR if the
	 * user has a null authentication token */
	public static final int PAM_DISALLOW_NULL_AUTHTOK       =0x0001;

	/* Note: these flags are used for pam_setcred() */

	/* Set user credentials for an authentication service */
	public static final int PAM_ESTABLISH_CRED              =0x0002;

	/* Delete user credentials associated with an authentication service */
	public static final int PAM_DELETE_CRED                 =0x0004;

	/* Reinitialize user credentials */
	public static final int PAM_REINITIALIZE_CRED           =0x0008;

	/* Extend lifetime of user credentials */
	public static final int PAM_REFRESH_CRED                =0x0010;

	/* Note: these flags are used by pam_chauthtok */

	/* The password service should only update those passwords that have
	 * aged.  If this flag is not passed, the password service should
	 * update all passwords. */
	public static final int PAM_CHANGE_EXPIRED_AUTHTOK      =0x0020;

	/* ------------------ The Linux-PAM item types ------------------- */

	/* these defines are used by pam_set_item() and pam_get_item() */

	//public static final int PAM_SERVICE       = 1;    /* The service name */
	//public static final int PAM_USER          = 2;    /* The user name */
	//public static final int PAM_TTY           = 3;    /* The tty name */
	//public static final int PAM_RHOST         = 4;    /* The remote host name */
	//public static final int PAM_CONV          = 5;    /* The pam_conv structure */

	//public static final int PAM_RUSER         = 8;    /* The remote user name */
	//public static final int PAM_USER_PROMPT   = 9;    /* the prompt for getting a username */
	//public static final int PAM_FAIL_DELAY    = 10;   /* app supplied function to override failure
	//                                   									delays */
	
	private PamCallback callback;
	private int status;
	private boolean valid = false;
	private byte[] nativeData;
	
	public Pam(String service, String user, PamCallback callback)
	{
		this.callback=callback;
		status=call_pam_start(service,user,callback);
		if (status!=PAM_SUCCESS)
		{
			throw new RuntimeException("Unable to initialise pam");
		}
		valid=true;
	}
	
	private void setNativeData(byte[] data)
	{
		nativeData=data;
	}
	
	private byte[] getNativeData()
	{
		return nativeData;
	}
	
	public void finalize() throws Throwable
	{
		if (valid)
			pam_end(getStatus());
	}
	
	static
	{
		System.loadLibrary("pamcalls");
	}
	
	private native int call_pam_start(String service, String user, PamCallback callback);
	private native int call_pam_end(int pam_status);
	private native int call_pam_authenticate(int flags);
	private native int call_pam_setcred(int flags);
	private native int call_pam_acct_mgmt(int flags);
	private native int call_pam_open_session(int flags);
	private native int call_pam_close_session(int flags);
	private native int call_pam_chauthtok(int flags);
	private native String call_pam_strerror(int errnum);
	
	public int getStatus()
	{
		return status;
	}
	
	public String getError()
	{
		if (!valid)
			throw new IllegalStateException("pam_end has already been called");
		return call_pam_strerror(status);
	}
	
	public int pam_end(int pam_status)
	{
		if (!valid)
			throw new IllegalStateException("pam_end has already been called");
		status=call_pam_end(pam_status);
		valid=false;
		return status;
	}
	
	public int pam_authenticate(int flags)
	{
		if (!valid)
			throw new IllegalStateException("pam_end has already been called");
		status=call_pam_authenticate(flags);
		return status;
	}
	
	public int pam_setcred(int flags)
	{
		if (!valid)
			throw new IllegalStateException("pam_end has already been called");
		status=call_pam_setcred(flags);
		return status;
	}
	
	public int pam_acct_mgmt(int flags)
	{
		if (!valid)
			throw new IllegalStateException("pam_end has already been called");
		status=call_pam_acct_mgmt(flags);
		return status;
	}
	
	public int pam_open_session(int flags)
	{
		if (!valid)
			throw new IllegalStateException("pam_end has already been called");
		status=call_pam_open_session(flags);
		return status;
	}
	
	public int pam_close_session(int flags)
	{
		if (!valid)
			throw new IllegalStateException("pam_end has already been called");
		status=call_pam_close_session(flags);
		return status;
	}
	
	public int pam_chauthtok(int flags)
	{
		if (!valid)
			throw new IllegalStateException("pam_end has already been called");
		status=call_pam_chauthtok(flags);
		return status;
	}
}
