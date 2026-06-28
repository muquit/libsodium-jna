package com.muquit.libsodiumjna.exceptions;

public class SodiumLibraryException extends Exception
{

	private static final long serialVersionUID = 30349089390987L;

    public SodiumLibraryException() {}

    public SodiumLibraryException(final String message)
    {
        super(message);
    }

    public SodiumLibraryException(final Throwable cause)
    {
        super(cause);
    }

    public SodiumLibraryException(final String message, final Throwable cause)
    {
        super(message, cause);
    }
}
