package com.blueprintit.security.pam;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * @author Dave
 */
public class PamLoginModule implements LoginModule, PamCallback
{
	private Subject subject;
	private CallbackHandler callback;
	private Pam pam;
	private boolean loggedin = false;
	private Map sharedState;
	private Map options;
	
	public void initialize(Subject subject, CallbackHandler callback, Map sharedState, Map options)
	{
		this.sharedState=sharedState;
		this.subject=subject;
		this.callback=callback;
		this.options=options;
	}

	private void cleanExit(String message) throws LoginException
	{
		pam.pam_end(pam.getStatus());
		throw new LoginException(message);
	}
	
	public boolean login() throws LoginException
	{
		String username = (String)sharedState.get("javax.security.auth.login.name");
		if (username!=null)
		{
			NameCallback namecheck = new NameCallback("Username:");
			try
			{
				callback.handle(new Callback[] {namecheck});
				username=namecheck.getName();
				sharedState.put("javax.security.auth.login.name",username);
			}
			catch (Exception e)
			{
				throw new LoginException("Unable to get username");
			}
		}
		pam = new Pam("java_auth",username,this);
		loggedin = (pam.pam_authenticate(0)==Pam.PAM_SUCCESS);
		return loggedin;
	}

	public boolean commit() throws LoginException
	{
		if (loggedin)
		{
			if (pam.pam_acct_mgmt(0)!=Pam.PAM_SUCCESS)
				cleanExit("User's account has expired");
			if (pam.pam_setcred(Pam.PAM_ESTABLISH_CRED)!=Pam.PAM_SUCCESS)
				cleanExit("Could not establish credentials");
			if (pam.pam_open_session(0)!=Pam.PAM_SUCCESS)
				cleanExit("Could not open authenticated session");
			return true;
		}
		else
		{
			return false;
		}
	}

	public boolean abort() throws LoginException
	{
		pam.pam_end(pam.getStatus());
		return loggedin;
	}

	public boolean logout() throws LoginException
	{
		if (pam.pam_close_session(0)!=Pam.PAM_SUCCESS)
			cleanExit("Could not close session");
		if (pam.pam_setcred(Pam.PAM_DELETE_CRED)!=Pam.PAM_SUCCESS)
			cleanExit("Could not remove credentials");
		pam.pam_end(pam.getStatus());
		return false;
	}

	public String fetchUsername()
	{
		
	}
	
	public String fetchPassword()
	{
		
	}
	
	public PamResponse[] callback(PamMessage[] messages)
	{
		PamResponse[] results = new PamResponse[messages.length];
		List callbacks = new ArrayList();
		for (int loop=0; loop<messages.length; loop++)
		{
			switch (messages[loop].getStyle())
			{
				case PamMessage.PAM_ERROR_MSG:
					callbacks.add(new TextOutputCallback(TextOutputCallback.ERROR,messages[loop].getMessage()));
					break;
				case PamMessage.PAM_TEXT_INFO:
					callbacks.add(new TextOutputCallback(TextOutputCallback.INFORMATION,messages[loop].getMessage()));
					break;
				case PamMessage.PAM_PROMPT_ECHO_OFF:
					if (!sharedState.containsKey("javax.security.auth.login.password"))
					{
						callbacks.add(new PasswordCallback(messages[loop].getMessage(),false));
					}
					break;
				case PamMessage.PAM_PROMPT_ECHO_ON:
					if (!sharedState.containsKey("javax.security.auth.login.name"))
					{
						callbacks.add(new NameCallback(messages[loop].getMessage()));
					}
					break;
			}
		}
		Callback[] calls = new Callback[callbacks.size()];
		callbacks.toArray(calls);
		try
		{
			callback.handle(calls);
		}
		catch (Exception e)
		{
			return null;
		}
		int pos = 0;
		for (int loop=0; loop<messages.length; loop++)
		{
			switch (messages[loop].getStyle())
			{
				case PamMessage.PAM_ERROR_MSG:
				case PamMessage.PAM_TEXT_INFO:
					results[loop] = new PamResponse("");
					pos++;
					break;
				case PamMessage.PAM_PROMPT_ECHO_OFF:
					if (!sharedState.containsKey("javax.security.auth.login.password"))
					{
						String password = new String(((PasswordCallback)calls[pos]).getPassword());
						sharedState.put("javax.security.auth.login.password",password);
						results[loop] = new PamResponse(password);
						pos++;
					}
					else
					{
						results[loop] = new PamResponse((String)sharedState.get("javax.security.auth.login.password"));
					}
					break;
				case PamMessage.PAM_PROMPT_ECHO_ON:
					if (!sharedState.containsKey("javax.security.auth.login.name"))
					{
						String username = ((NameCallback)calls[pos]).getName();
						sharedState.put("javax.security.auth.login.name",username);
						results[loop] = new PamResponse(username);
						pos++;
					}
					else
					{
						results[loop] = new PamResponse((String)sharedState.get("javax.security.auth.login.password"));
					}
					break;
				default:
					results[loop] = new PamResponse("");
			}
		}
		return results;
	}
}
