package com.blueprintit.security.pam;

/**
 * @author Dave
 */
public class PamResponse
{
	private String response;
	private int code;
	
	public PamResponse(String message, int code)
	{
		this.code=code;
		this.response=message;
	}
	
	public PamResponse(String message)
	{
		this(message,0);
	}
	
	public String getResponse()
	{
		return response;
	}
	
	public int getResponseCode()
	{
		return code;
	}
}
