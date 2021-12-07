/**
 * JoseMain.java
 * @author tanjie
 * @date 2020:上午11:43:58
 * @version 1.0
 */
package com.test.dc.upi;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.cxf.common.util.Base64UrlUtility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Base64Utils;

import lombok.extern.slf4j.Slf4j;

/**
 * @ClassName JoseMain
 * @author tanjie
 * @Date 2020年2月20日
 * @Version 1.0.0
 */
@Slf4j
public class JoseMain {
	
	private static final Logger log = LoggerFactory.getLogger(JoseMain.class);
	
	private static String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjjkVt+Np+CuiiBg0PPOO/IZ7gcfBVeZhCK8oFLdYm0cEP3rbTkkOwBVBd3hLd0N1cgJyTiGBvLab6SJIlu5Xw0vc111kpbtw+5RPkOQhNzn5nS2/77vTvB6u1m6b4q5QCB+b+J8I/Zi/M/am5liejqklme+QkuO08VnDyKazdEo2VTdOIl1eZb2ohEZrKffPjRgDoPSsQF7KOvyuw9n4fl5E594QbBwOiVShTNVQExNfc0wHRjNbkiwjxCgSPT3byDyNhLoMTBbo02C1r4LOTikosYz93ndtou/bwkCNQ56+8DunNXXUKVENlnFxVy8ROB4qT9tGN7Negi2ZhXJK+wIDAQAB";
	private static String privateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCOORW342n4K6KIGDQ88478hnuBx8FV5mEIrygUt1ibRwQ/ettOSQ7AFUF3eEt3Q3VyAnJOIYG8tpvpIkiW7lfDS9zXXWSlu3D7lE+Q5CE3OfmdLb/vu9O8Hq7WbpvirlAIH5v4nwj9mL8z9qbmWJ6OqSWZ75CS47TxWcPIprN0SjZVN04iXV5lvaiERmsp98+NGAOg9KxAXso6/K7D2fh+XkTn3hBsHA6JVKFM1VATE19zTAdGM1uSLCPEKBI9PdvIPI2EugxMFujTYLWvgs5OKSixjP3ed22i79vCQI1Dnr7wO6c1ddQpUQ2WcXFXLxE4HipP20Y3s16CLZmFckr7AgMBAAECggEAfzStqTi9Wlvk1mcXqgCKPnEmXJDG6sbQuUy4w7atiMy/Duwa5O1RRRp94JZ2oSh0DlID3L/5Y0nNL3sbg+uQEbxzvSjqUZXSWyJu/AAfeV7gVOZLiufrXJHw/RgXU2tnZ6yl+3x7NR9+vMJ6ywIuZxkA6astG0SRXWFVTM1VKsexGVNkoUJk1gSRY7EwbiRZY0BU/WeFLM/flMu8oo5x9YPaiHDl2BYi0kQd8qJQtyF8NtuP32OR7RxSan4dT2uwPcmm6f86j3+TQknBK0Z2Jx+MBKxMlZpVqSOq2ZPjrcZs73eILUR80n8chuaRBH9owpyv7TC6tSTW/FIzTatAiQKBgQDbiKCANd4Nhg1IBQgGnbEckv347vcrL4G5oVXtJjOWEz3pXiw2QJ3Tk94sYVLVzwVoO29T84uW+X9Fc9Ot61GnwVq5vdfqejwRgKykGx0afr1vnBBUbmJXeY2IsUooIOli5Ov7so77UkLVjzfev6fsUSvtpC8zMCZ0V4Vvv8sDpwKBgQCl2Oy1xQVZVfw0ho1XLHmtPFRGVjRCXxCWxCGM/hbMICYZtBGwEIMEblDbfyIVq8y4eKKQT2d0BlwZ29v6AyzfL1rMoQxqCOirTQn1grzFpNT1J9iJTawpBIoxpFkYfqUMf39qS3kXV06UhQIQbXf3bwjmrsUly+Ylwzc9GR14jQKBgQCv1SeQaRS4SjUbCQSbn/P6ifUnS+bmTP+fOYyEDEPnIPRGlSneLjT7AIVDkJPzMgQHrwsE951HSABbFWFm/IKDVYegG2DzqgGwlxovupO94+NAoIQny92yaGYnJLDboTis/+POzf5dZ06mlDZQj7skuQLxLL6tRhSWvH7guYIWIwKBgHNaGPIoshq76qph98btQUhT0M4HQVv0oSYsDqXxSMv7hGSWUUMjiO05CXZRy9RE5SRdi7xR7kPN9Jtrx2nycXBekIoJbggGYEZdVBL2NvRFPHWznDGL27W/2ZrDk9CsrYGu4GF/Ux7/88Drbk8cxLdN/GPupWMvmckkKbSOVmg1AoGBALgYVNKAuxDmkBAfYGYqYe9IBrb3ds38wf2/QtQPRpXYIrNwIRsMJqglV5VPhCXOjbrmvgHi+IVD7Bjr61v06wlatUCLaIIAc60IgKEPEzVsGmWBB2QlZ7/5O3EcxRd1AS7NwCGF//XCxz+0FMhenJHKFzf9g07alerhzQhLvQV+";

	private static PublicKey publicK;
	private static PrivateKey privateK;
	
	static {
		/************************Get PublicKey object from public key string ***************************/
		byte[] publicKeyBytes = Base64Utils.decodeFromString(publicKey);
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory publicKeyFactory;
		try {
			publicKeyFactory = KeyFactory.getInstance("RSA");
			publicK = publicKeyFactory.generatePublic(publicKeySpec);
		} catch (Exception e) {
			log.error("publicKey get error",e);
		}
		
		/************************Get PrivateKey object from private key string ***************************/
		byte[] privateKeyBytes = Base64Utils.decodeFromString(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);    
        KeyFactory privateKeyFactory;
		try {
			privateKeyFactory = KeyFactory.getInstance("RSA");
			privateK = privateKeyFactory.generatePrivate(pkcs8KeySpec);
		} catch (Exception e) {
			log.error("privateKey get error",e);
		}    
	}
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String detachedJwsContent = "";
		//Transaction message sample
		String payload = "Upi@1234";
		
		/************************Generate JWS information***************************/
        try {
        	//Generate JWS information
        	String jwsContent = UpiJoseUtils.genJws(payload, "123456", "/v1/genkey", "00520446", privateK);
			log.info("JWS Header:"+new String(Base64UrlUtility.decode(jwsContent.substring(0, jwsContent.indexOf("."))), StandardCharsets.UTF_8));
			log.info("message for sign:"+jwsContent.substring(0, jwsContent.lastIndexOf(".")));
			log.info("complete-jws-content:"+jwsContent);
        	//Detached payload part,the value of detachedJwsContent can be used to the http header "UPI-JWS"
			detachedJwsContent = JwsUtil.detachedJwsContent(jwsContent);
			log.info("detached-jws-content:"+detachedJwsContent);
		} catch (Exception e) {
			log.error("genJws error",e);
		}
        
        /************************Verify JWS information***************************/
        try {
        	//Combine the detachedJwsContent part and payload part into jwsContent
        	String jwsContent = JwsUtil.packageJws(detachedJwsContent, payload);
        	//Verify the value of jwsContent
			boolean result = UpiJoseUtils.parseJws(jwsContent, publicK);
			log.info("jws verify result:"+result);
		} catch (Exception e) {
			log.error("parseJws error",e);
		}
        
        //Get cert id from the value of detachedJwsContent
        String jwsKid = JwsUtil.getJwsKid(detachedJwsContent);
        log.info("cert-id:"+jwsKid);
        
        /************************Generate JWE information***************************/
        String jweContent = "";
        try {
        	//Generate jweContent
			jweContent = UpiJoseUtils.genJwe(payload, publicK, "1562032885962");
			log.info("jwe-content:"+jweContent);
		} catch (Exception e) {
			log.error("genJwe error",e);
		}
        
        /************************Parse JWE information***************************/
        try {
        	//Parse the jweContent
			String plainText = UpiJoseUtils.parseJwe(jweContent, privateK);
			log.info("plain-text:"+plainText);
		} catch (Exception e) {
			log.error("parseJwe error",e);
		}
        
        //Get cert id from jweContent
        String jweKid = JwsUtil.getJweKid(jweContent);
        log.info("cert-id:"+jweKid);
		

	}

}
