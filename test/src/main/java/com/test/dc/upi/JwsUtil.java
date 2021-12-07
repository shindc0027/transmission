/**
 * JwsUtil.java
 * @author tanjie
 * @date 2019:下午4:31:43
 * @version 1.0
 */
package com.test.dc.upi;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.cxf.common.util.Base64UrlUtility;
import org.apache.cxf.rs.security.jose.jwe.JweCompactConsumer;
import org.apache.cxf.rs.security.jose.jws.JwsCompactConsumer;
import org.bouncycastle.util.encoders.Hex;

/**
 * @ClassName JwsUtil
 * @author tanjie
 * @Date 2019年7月10日
 * @Version 1.0.0
 */
public class JwsUtil {
	
	public static String packageJws(String detachedJwsContent, String payload) {
		String[] parts = getCompactParts(detachedJwsContent);
		String payloadBase64Url = Base64UrlUtility.encode(payload);
		String jwsContent = parts[0]+"."+payloadBase64Url+"."+parts[2];
		return jwsContent;
	}

	public static String packageJwsApp(String detachedJwsContent, String payload) {
		String[] parts = getCompactParts(detachedJwsContent);
		String payloadBase64Url = JwsUtil.encodeToUrlSafeString(payload.getBytes(StandardCharsets.UTF_8));
		String jwsContent = parts[0]+"."+payloadBase64Url+"."+parts[2];
		return jwsContent;
	}
	
	public static String detachedJwsContent(String jwsContent) {
		String[] parts = getCompactParts(jwsContent);
		String detachedJwsContent = parts[0]+"."+"."+parts[2];
		return detachedJwsContent;
	}
	
	public static String[] getCompactParts(String compactContent) {
        if (compactContent.startsWith("\"") && compactContent.endsWith("\"")) {
            compactContent = compactContent.substring(1, compactContent.length() - 1);
        }
//        return StringUtils.split(compactContent, "\\.");
        return compactContent.split("\\.");
    }
	
	public static String getJwsKid(String jwsContent) {
		
		JwsCompactConsumer jwsCompactConsumer = new JwsCompactConsumer(jwsContent);
		
        return jwsCompactConsumer.getJwsHeaders().getKeyId();
    }
	
	public static String getJweKid(String jweContent) {
		
		JweCompactConsumer consumer = new JweCompactConsumer(jweContent);
		
		return consumer.getJweHeaders().getKeyId();
    }
	
	public static String getJwsUuid(String jwsContent) {
		
		JwsCompactConsumer jwsCompactConsumer = new JwsCompactConsumer(jwsContent);
		
        return (String) jwsCompactConsumer.getJwsHeaders().getHeader("UPI-UUID");
    }

	/**
	 * 生成HMAC
	 * @param key
	 * @param msg
	 * @return
	 * @throws Exception
	 */
	public static String genHmac(String key, String msg) throws Exception {
		Mac mac = Mac.getInstance("HmacSHA256");
		byte[] keyByte = Hex.decode(key);
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyByte, "HmacSHA256");
		mac.init(secretKeySpec);
		byte[] content = msg.getBytes(StandardCharsets.UTF_8);
		mac.update(content,0,content.length);

		return JwsUtil.encodeToUrlSafeString(mac.doFinal());
	}

	public static boolean isEmpty(String str) {

		return null == str || "".equals(str.trim()) || "null".equals(str) || "(null)".equals(str);
	}

	public static String encodeToUrlSafeString(byte[] in ){

		//return Base64.encodeToString(in,Base64.URL_SAFE|Base64.NO_WRAP|Base64.NO_PADDING);
		return Base64.getUrlEncoder().encodeToString(in);
	}

	public static byte[] decodeFromUrlSafeString(String src ){

		//return Base64.decode(src, Base64.URL_SAFE);
		return Base64.getUrlDecoder().decode(src);
	}
}
