package com.blueprintit.security.pam;

/**
 * @author Dave
 */
public class PamAuthenticate implements PamCallback
{
	private PamAuthenticate(String user, String password)
	{
		
	}

	public PamResponse[] callback(PamMessage[] messages)
	{
		// TODO Auto-generated method stub
		return null;
	}
	
	public static boolean authenticate(String user, String password)
	{
		PamAuthenticate callback = new PamAuthenticate(user,password);
		Pam pam = new Pam("java_auth",user,callback);
		boolean result = (pam.pam_authenticate(Pam.PAM_SILENT)==Pam.PAM_SUCCESS);
		pam.pam_end(pam.getStatus());
		return result;
	}
	
	public static void main(String[] args)
	{
		if (args.length==2)
		{
			if (authenticate(args[0],args[1]))
			{
				System.out.println("Authentication succeeded");
			}
			else
			{
				System.out.println("Authentication failed");
			}
		}
		else
		{
			System.err.println("You must supply a username and password");
		}
	}
}
