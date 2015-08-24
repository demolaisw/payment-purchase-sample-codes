package com.interswitchng.techquest.payment.purchase.sample.codes.utils;

import hsmprobe.util.HexConverter;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import com.interswitchng.techquest.system.service.util.api.SystemConstantsApi;
import com.interswitchng.techquest.system.service.util.exception.SystemException;

public class SecureDecryptor {
	
	static Cipher encryptCipher;
	static Cipher decryptCipher;
	static SecureDecryptor secureDecryptor = null;
	private static final Object encryptCipherLock = new Object();
	private static final Object encryptSecureCipherLock = new Object();
    private static final Object decryptCipherLock = new Object();
    static RSAEngine rsaEngine = new RSAEngine();
    
	private static final transient Log LOG = LogFactory.getLog(SecureDecryptor.class);
	
	private SecureDecryptor(Cipher encryptCipher, Cipher decryptCipher){
		SecureDecryptor.encryptCipher = encryptCipher;
		SecureDecryptor.decryptCipher = decryptCipher;
	}
	
	public static SecureDecryptor getInstance(SystemConstantsApi systemConstantsApi, String payphoneModulus, String payphonePrivateExponent, String payphonePublicExponent) throws SystemException{
		
		if (secureDecryptor == null)
		{
			try 
			{
				Cipher encryptCipher = null;
				Cipher decryptCipher = null;
				Security.addProvider(new BouncyCastleProvider());
				RSAPrivateKeySpec privateKeyspec = new RSAPrivateKeySpec(new BigInteger(payphoneModulus, 16), new BigInteger(payphonePrivateExponent, 16));
				KeyFactory factory = KeyFactory.getInstance("RSA"); //, "JHBCI");
				PrivateKey privateKey = factory.generatePrivate(privateKeyspec);
				decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
				decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
				
				
				RSAPublicKeySpec publicKeyspec = new RSAPublicKeySpec(new BigInteger(payphoneModulus, 16), new BigInteger(payphonePublicExponent, 16));
				PublicKey publicKey = factory.generatePublic(publicKeyspec);
				encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
				encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);		
				
				BigInteger modulusByte = new BigInteger(Hex.decode("00" + payphoneModulus));
		        BigInteger exponentByte = new BigInteger(Hex.decode(payphonePublicExponent));
		        RSAKeyParameters pkParameters = new RSAKeyParameters(false, modulusByte, exponentByte);
		        rsaEngine.init(true, pkParameters);
				
				LOG.debug("SecureDecryptor Initiated Successfully");
				secureDecryptor = new SecureDecryptor(encryptCipher, decryptCipher);
			} catch (Exception e) {
				LOG.error("Error while intializing SecureDecryptor: " + e);
				throw new SystemException(systemConstantsApi.getErrorBadCryptoCode(), e);
			}			
		}		
		return secureDecryptor;
	}
	
	
	public String encryptSecure(byte[] secureBytes, SystemConstantsApi systemConstantsApi) throws SystemException
	{
		try {
			String secureData = null;
			synchronized (encryptSecureCipherLock) {
				byte[] encryptedSecureBytes = rsaEngine.processBlock(secureBytes, 0, secureBytes.length);
				byte[] encryptedSecureHexBytes = Hex.encode(encryptedSecureBytes);
				secureData = new String(encryptedSecureHexBytes);
			}
			return secureData;
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new SystemException(systemConstantsApi.getErrorBadCryptoCode(), ex);
		}
	} 
	
	
	public byte[] encrypt(String data, SystemConstantsApi systemConstantsApi) throws SystemException
	{
		try {
			byte[] secureData = null;
			synchronized (encryptCipherLock) {
				secureData = encryptCipher.doFinal(data.getBytes("UTF8"));
				System.out.println(HexConverter.fromBinary2Hex(secureData));
			}
			return secureData;
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new SystemException(systemConstantsApi.getErrorBadCryptoCode(), ex);
		}
	} 
	
	public byte[] decrypt(String data, SystemConstantsApi systemConstantsApi) throws SystemException
	{
		try {
			byte[] secureData = null;
			synchronized (decryptCipherLock) {
				secureData = decryptCipher.doFinal(HexConverter.fromHex2ByteArray(data.getBytes("UTF8")));
			}
			return secureData;
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new SystemException(systemConstantsApi.getErrorBadCryptoCode(), ex);
		}
	}

	
}
