package com.blueprintit.security.pam;

/**
 * @author Dave
 */
public class PamResponse
{
	private String response;
	
	public PamResponse(String message)
	{
		response=message;
	}
	
	public String getResponse()
	{
		return response;
	}
	
	public int getResponseCode()
	{
		return 0;
	}
}
