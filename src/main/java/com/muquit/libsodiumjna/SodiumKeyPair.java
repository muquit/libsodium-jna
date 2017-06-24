package com.muquit.libsodiumjna;

/**
 * A class just to hold public and private keys. The crypto code is in
 * SodidumLibary class
 * @author muquit@muquit.com - Oct 21, 2016, 11:35:44 AM - first cut
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
