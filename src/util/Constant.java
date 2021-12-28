package util;

import java.util.Base64;

public class Constant {
	public static final Base64.Encoder encoder = Base64.getEncoder();
	public static final Base64.Decoder decoder = Base64.getDecoder();
	public static final String DEFAULT_SELECTION = "None";
	public static final String PUBLIC_KEY_FILE_NAME = "public.key";
	public static final String PRIVATE_KEY_FILE_NAME = "private.key";
	public static final String UNICODE_FORMAT = "UTF-8";
	public static final String TEXT_TYPE = "text";
	public static final String FILE_TYPE = "file";
	public static final String ENCRYPT_PREFIX = "encrypted-file";
	public static final String DECRYPT_PREFIX = "decrypted-file";
}
