package com.blueprintit.security.pam;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * @author Dave
 */
public class PamLoginModule implements LoginModule
{
	/* (non-Javadoc)
	 * @see javax.security.auth.spi.LoginModule#initialize(javax.security.auth.Subject, javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
	 */
	public void initialize(Subject arg0, CallbackHandler arg1, Map arg2, Map arg3)
	{
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see javax.security.auth.spi.LoginModule#login()
	 */
	public boolean login() throws LoginException
	{
		// TODO Auto-generated method stub
		return false;
	}

	/* (non-Javadoc)
	 * @see javax.security.auth.spi.LoginModule#commit()
	 */
	public boolean commit() throws LoginException
	{
		// TODO Auto-generated method stub
		return false;
	}

	/* (non-Javadoc)
	 * @see javax.security.auth.spi.LoginModule#abort()
	 */
	public boolean abort() throws LoginException
	{
		// TODO Auto-generated method stub
		return false;
	}

	/* (non-Javadoc)
	 * @see javax.security.auth.spi.LoginModule#logout()
	 */
	public boolean logout() throws LoginException
	{
		// TODO Auto-generated method stub
		return false;
	}
}
