package com.blueprintit.security.pam;

/**
 * @author Dave
 */
public interface PamCallback
{
	public PamResponse[] callback(PamMessage[] messages);
}
