package com.muquit.libsodiumjna;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A helper class to convert hex to binary and vice versa.
 * I get confused with encode decode methods of Hex class and
 * always have to look it up!
 * @author muquit@muquit.com - Oct-09-2016
 */

public class SodiumUtils
{
    private final static Logger logger = LoggerFactory.getLogger(SodiumUtils.class);
    
    public static byte[] hex2Binary(String hexString)
    {
        byte[] data = null;
        try
        {
            data = Hex.decodeHex(hexString.toCharArray());
        } catch (DecoderException e)
        {
            e.printStackTrace();
            logger.error("Exception caught: " + e.getLocalizedMessage());
            return null;
        }
        return data;
    }
    
    public static String binary2Hex(byte[] data)
    {
        String hexString = Hex.encodeHexString(data);
        return hexString;
    }
    

}
