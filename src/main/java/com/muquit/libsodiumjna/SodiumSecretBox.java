package com.muquit.libsodiumjna;

/**
 * Class to hold cipher text and mac for secret box
 * @author muquit@muquit.com - Oct 22, 2016
 */
public class SodiumSecretBox
{
    private byte[] cipherText;
    private byte[] mac;
    
    public byte[] getCipherText()
    {
        return this.cipherText;
    }
    
    public byte[] getMac()
    {
        return this.mac;
    }
    
    public void setCipherText(byte[] cipherText)
    {
        this.cipherText = cipherText;
    }
    
    public void setMac(byte[] mac)
    {
        this.mac = mac;
    }
}
