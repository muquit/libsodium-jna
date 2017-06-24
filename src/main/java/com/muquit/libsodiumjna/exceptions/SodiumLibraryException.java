package com.muquit.libsodiumjna.exceptions;

public class SodiumLibraryException extends Exception
{

	private static final long serialVersionUID = 30349089390987L;
    private String message;
    
    public SodiumLibraryException() { message = null; }

    public SodiumLibraryException(final String message)
    {
        super(message);
        this.message = message;
    }

    public SodiumLibraryException(final Throwable cause)
    {
        super(cause);
        message = (cause != null) ? cause.getMessage() : null;
    }

    public SodiumLibraryException(final String message, final Throwable cause)
    {
        super(message,cause);
        this.message = message;
    }

    public String getMessage()
    {
        return message;
    }	
}
