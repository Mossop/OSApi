package com.blueprintit.security.pam;

/**
 * @author Dave
 */
public class PamMessage
{
	/* Message styles */

	public static final int PAM_PROMPT_ECHO_OFF    = 1;
	public static final int PAM_PROMPT_ECHO_ON     = 2;
	public static final int PAM_ERROR_MSG          = 3;
	public static final int PAM_TEXT_INFO          = 4;

	private String message;
	private int style;
	
	public PamMessage(int style, String message)
	{
		this.message=message;
		this.style=style;
	}
	
	public int getStyle()
	{
		return style;
	}
	
	public String getMessage()
	{
		return message;
	}
}
