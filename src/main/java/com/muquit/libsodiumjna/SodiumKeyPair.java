package com.muquit.libsodiumjna;

/**
 * A class to hold the public and private key pairs used by {@link SodiumLibrary#cryptoBoxKeyPair()}
 */
public class SodiumKeyPair
{
    private byte[] publicKey;
    private byte[] privateKey;
    
    public SodiumKeyPair() {}
    
    public SodiumKeyPair(byte[] publicKey, byte[] privatekey)
    {
    	setPublicKey(publicKey);
    	setPrivateKey(privatekey);
    }
    
    public byte[] getPublicKey()
    {
        return this.publicKey;
    }
    
    public byte[] getPrivateKey()
    {
        return this.privateKey;
    }
    
    public void setPublicKey(byte[] publicKey)
    {
    	this.publicKey = publicKey;
    }
    
    public void setPrivateKey(byte[] privateKey)
    {
    	this.privateKey = privateKey;
    }
}
