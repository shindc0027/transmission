/**
 * 
 */
package com.test.dc.upi;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.UUID;

import org.apache.cxf.common.util.Base64UrlUtility;
import org.apache.cxf.rs.security.jose.jwa.ContentAlgorithm;
import org.apache.cxf.rs.security.jose.jwa.KeyAlgorithm;
import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwe.AesCbcHmacJweDecryption;
import org.apache.cxf.rs.security.jose.jwe.AesCbcHmacJweEncryption;
import org.apache.cxf.rs.security.jose.jwe.JweDecryptionOutput;
import org.apache.cxf.rs.security.jose.jwe.JweDecryptionProvider;
import org.apache.cxf.rs.security.jose.jwe.JweEncryptionProvider;
import org.apache.cxf.rs.security.jose.jwe.JweHeaders;
import org.apache.cxf.rs.security.jose.jwe.RSAKeyDecryptionAlgorithm;
import org.apache.cxf.rs.security.jose.jwe.RSAKeyEncryptionAlgorithm;
import org.apache.cxf.rs.security.jose.jws.HmacJwsSignatureVerifier;
import org.apache.cxf.rs.security.jose.jws.JwsCompactConsumer;
import org.apache.cxf.rs.security.jose.jws.JwsCompactProducer;
import org.apache.cxf.rs.security.jose.jws.JwsHeaders;
import org.apache.cxf.rs.security.jose.jws.PrivateKeyJwsSignatureProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import com.google.gson.Gson;

/**
 * @ClassName UpiJoseUtils
 * @author tanjie
 * @Date 2019年10月21日
 * @Version 1.0.0
 */
public class UpiJoseUtils {
	
	public static String genJws(String message, String kid, String requestPath, String appId, PrivateKey privateK) throws Exception	{
		
		return genJws(message, kid, null, requestPath, appId, privateK);
	}
	
	public static String genJws(String message, String kid, String uuid, String requestPath, String appId, PrivateKey privateK) throws Exception   {
		
		JwsHeaders jwsHeaders = new JwsHeaders(SignatureAlgorithm.RS256);
		
		jwsHeaders.setKeyId(kid);
		
		LinkedList<String> crit = new LinkedList<>();
		crit.add("UPI-UUID");//uuid,timestamp,appid,reqpath
		crit.add("UPI-TIMESTAMP");
		crit.add("UPI-APPID");
		if(!JwsUtil.isEmpty(requestPath)) {
			crit.add("UPI-REQPATH");
		}
		
		jwsHeaders.setCritical(crit);
		if(JwsUtil.isEmpty(uuid)) {
			jwsHeaders.setHeader("UPI-UUID", UUID.randomUUID().toString().replaceAll("-", ""));
		}else {
			jwsHeaders.setHeader("UPI-UUID", uuid);
		}
		jwsHeaders.setHeader("UPI-TIMESTAMP", String.valueOf(System.currentTimeMillis()/1000));
		jwsHeaders.setHeader("UPI-APPID", appId);
		if(!JwsUtil.isEmpty(requestPath)) {
			jwsHeaders.setHeader("UPI-REQPATH", requestPath);
		}
		
		//支持紧凑的序列
		JwsCompactProducer jwsProducer = new JwsCompactProducer(jwsHeaders,message);
		
		jwsProducer.signWith(new PrivateKeyJwsSignatureProvider(privateK,SignatureAlgorithm.RS256));
		
		return jwsProducer.getSignedEncodedJws();
	}
	
	public static boolean parseJws(String jwsStr, PublicKey publicK) throws Exception {
		
		JwsCompactConsumer jwsCompactConsumer = new JwsCompactConsumer(jwsStr);
		
		return jwsCompactConsumer.verifySignatureWith(publicK, SignatureAlgorithm.RS256);
	}
	
	public static String genJwe(String content, PublicKey publicK, String kid) throws Exception {
		
		Security.addProvider(new BouncyCastleProvider());
		
    	RSAKeyEncryptionAlgorithm rsaKeyEncryptionAlgorithm = new RSAKeyEncryptionAlgorithm((RSAPublicKey) publicK,KeyAlgorithm.RSA1_5,false);
    	
    	String uuid = UUID.randomUUID().toString().replaceAll("-", "");
    	
		byte[] cek = uuid.getBytes(StandardCharsets.UTF_8);
		
		//iv必须是16 bytes
		byte[] iv = UUID.randomUUID().toString().replaceAll("-", "").substring(0, 16).getBytes(StandardCharsets.UTF_8);
		
		JweEncryptionProvider encryptor = new AesCbcHmacJweEncryption(ContentAlgorithm.A128CBC_HS256,cek,iv,rsaKeyEncryptionAlgorithm);
		
		JweHeaders jweHeaders = new JweHeaders(KeyAlgorithm.RSA1_5, ContentAlgorithm.A128CBC_HS256);
		
		jweHeaders.setKeyId(kid);
		
		String jweContent = encryptor.encrypt(content.getBytes("UTF-8"), jweHeaders);
		
		return jweContent;
	}
	
	public static String parseJwe(String jweContent, PrivateKey privateK) throws Exception {
		
		Security.addProvider(new BouncyCastleProvider());
		
		RSAKeyDecryptionAlgorithm keyDecryptionAlgorithm = new RSAKeyDecryptionAlgorithm((RSAPrivateKey) privateK, KeyAlgorithm.RSA1_5,false);
		
		JweDecryptionProvider decryptor = new AesCbcHmacJweDecryption(keyDecryptionAlgorithm,ContentAlgorithm.A128CBC_HS256);
		
		JweDecryptionOutput decrypt = decryptor.decrypt(jweContent);
		
		String contentText = decrypt.getContentText();
		
		return contentText;
	}

	/**
	 * HS256生成JWS
	 * @param message
	 * @param kid 使用HS256算法时，kid 为Passphrase值
	 * @param reqPath
	 * @param uuid
	 * @param appId
	 * @return
	 * @throws Exception
	 */
	public static String genJwsHS(String message,String kid, String reqPath, String uuid, String appId, String key) throws Exception {

		JwsHeaders jwsHeaders = new JwsHeaders(SignatureAlgorithm.HS256);

		jwsHeaders.setKeyId(kid);

		LinkedList<String> crit = new LinkedList<>();
		crit.add("UPI-UUID");
		crit.add("UPI-TIMESTAMP");
		crit.add("UPI-APPID");
		if(!JwsUtil.isEmpty(reqPath)) {
			crit.add("UPI-REQPATH");
		}

		jwsHeaders.setCritical(crit);
		if(JwsUtil.isEmpty(uuid)) {
			jwsHeaders.setHeader("UPI-UUID", UUID.randomUUID().toString().replaceAll("-", ""));
		}else {
			jwsHeaders.setHeader("UPI-UUID", uuid);
		}
		jwsHeaders.setHeader("UPI-TIMESTAMP", String.valueOf(System.currentTimeMillis()/1000));
		jwsHeaders.setHeader("UPI-APPID", appId);
		if(!JwsUtil.isEmpty(reqPath)) {
			jwsHeaders.setHeader("UPI-REQPATH", reqPath);
		}

		//支持紧凑的序列
		JwsCompactProducer jwsProducer = new JwsCompactProducer(jwsHeaders,message);
		String jwsU = jwsProducer.getUnsignedEncodedJws();

		String signHmac = JwsUtil.genHmac(key,jwsU);

		jwsProducer.setSignatureBytes(Base64UrlUtility.decode(signHmac));

		return jwsProducer.getSignedEncodedJws();
	}

	/**
	 * HS256验证验签
	 * @param jwsStr
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static boolean parseJwsHS(String jwsStr,String key) throws Exception {
		JwsCompactConsumer jwsConsumer = new JwsCompactConsumer(jwsStr);
		return jwsConsumer.verifySignatureWith(new HmacJwsSignatureVerifier(Hex.decode(key), SignatureAlgorithm.HS256));
	}

	/**
	 * HS256生成JWS手动
	 * @param message
	 * @param kid 使用HS256算法时，kid 为Passphrase值
	 * @param reqPath
	 * @param uuid
	 * @param appId
	 * @return
	 * @throws Exception
	 */
	public static String genJwsHSManul(String message,String kid, String reqPath, String uuid, String appId, String key) throws Exception {

		HashMap<String,Object> jwsHeaders = new HashMap<>();
		jwsHeaders.put("alg","HS256");
		jwsHeaders.put("kid",kid);

		LinkedList<String> crit = new LinkedList<>();
		crit.add("UPI-UUID");
		crit.add("UPI-TIMESTAMP");
		crit.add("UPI-APPID");
		if(!JwsUtil.isEmpty(reqPath)) {
			crit.add("UPI-REQPATH");
		}

		jwsHeaders.put("crit",crit);

		if(JwsUtil.isEmpty(uuid)) {
			jwsHeaders.put("UPI-UUID", UUID.randomUUID().toString().replaceAll("-", ""));
		}else {
			jwsHeaders.put("UPI-UUID", uuid);
		}
		jwsHeaders.put("UPI-TIMESTAMP", String.valueOf(System.currentTimeMillis()/1000));
		jwsHeaders.put("UPI-APPID", appId);
		if(!JwsUtil.isEmpty(reqPath)) {
			jwsHeaders.put("UPI-REQPATH", reqPath);
		}

		String jwsHeadersStr = new Gson().toJson(jwsHeaders); 
		
		//支持紧凑的序列
		String unsignJws = JwsUtil.encodeToUrlSafeString(jwsHeadersStr.getBytes(StandardCharsets.UTF_8))
				+"."+JwsUtil.encodeToUrlSafeString(message.getBytes(StandardCharsets.UTF_8));

		String signHmac = JwsUtil.genHmac(key,unsignJws);

		return unsignJws+"."+signHmac;
	}

	/**
	 * HS256验证验签手动
	 * @param jwsStr
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static boolean parseJwsHSManul(String jwsStr,String key) throws Exception {

		String[] split = jwsStr.split("\\.");
		String signHmac = JwsUtil.genHmac(key,split[0]+"."+split[1]);
		return MessageDigest.isEqual(JwsUtil.decodeFromUrlSafeString(signHmac), JwsUtil.decodeFromUrlSafeString(split[2]));
	}
}
