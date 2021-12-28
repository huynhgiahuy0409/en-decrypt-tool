package agorithms;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.swing.JOptionPane;

import org.apache.commons.lang3.RandomStringUtils;

import gui.GUI;

public class PBESymmetricSecurity {
	private static final String ALGORITHM = "PBEWithHmacSHA1AndAES_128";
	private static final int ITERATION_COUNT = 20;
	private static final String UNICODE_FORMAT = "UTF-8";
	private static Cipher pbeCipher;
	private GUI gui;
	private static Base64.Encoder encoder = Base64.getEncoder();
	private static Base64.Decoder decoder = Base64.getDecoder();
	private byte[] saltValue;

	public PBESymmetricSecurity(GUI gui) {
		super();
		this.gui = gui;
		saltValue = generateSALT();
	}

	public PBESymmetricSecurity() {
	}

	public static byte[] generateComplexPasswordOrSecretKeyValue() throws Exception {
		byte[] passwordOrKeyValue = RandomStringUtils.randomAscii(16).getBytes(UNICODE_FORMAT);
		KeySpec keySpec = new PBEKeySpec(new String(passwordOrKeyValue).toCharArray());
		SecretKey secretKey = SecretKeyFactory.getInstance(ALGORITHM).generateSecret(keySpec);
		return secretKey.getEncoded();
	}

	public byte[] generateSALT() {
		byte[] saltValue = null;
		{
			SecureRandom r = new SecureRandom();
			byte[] newSeed = r.generateSeed(8);
			r.setSeed(newSeed);
			saltValue = new byte[8];
			r.nextBytes(saltValue);
		}
		return saltValue;
	}

	public static int getIterationCount() {
		return ITERATION_COUNT;
	}

	public byte[] getSaltValue() {
		return saltValue;
	}

	public void setSaltValue(byte[] saltValue) {
		this.saltValue = saltValue;
	}

	public boolean generateKey(String password, String algorithmName, String destFilePath) {
		KeySpec keySpec = new PBEKeySpec(password.toCharArray());
		SecretKey secretKey = null;
		try {
			secretKey = SecretKeyFactory.getInstance(algorithmName).generateSecret(keySpec);
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			JOptionPane.showMessageDialog(this.gui, "Tạo khoá PBE: Không thành công");
			return false;
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			JOptionPane.showMessageDialog(this.gui, "Tạo khoá PBE: Thuật toán này không tồn tại");
			return true;
		}
		byte[] sKeyEncoded = secretKey != null ? secretKey.getEncoded() : null;
		if (sKeyEncoded == null) {
			return false;
		}
		File f = new File(destFilePath);

		if (f.exists()) {
			if (f.isDirectory()) {
				f = new File(destFilePath + "\\private-key.txt");
				try {
					f.createNewFile();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					JOptionPane.showMessageDialog(this.gui, "Tạo khoá PBE: IOException");
					return false;
				}
			}
		} else {
			JOptionPane.showMessageDialog(this.gui, "Tạo khoá PBE: Đường dẫn không hợp lệ");
			return false;
		}
		FileOutputStream fos;
		try {
			fos = new FileOutputStream(f);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			JOptionPane.showMessageDialog(this.gui, "Tạo khoá PBE: Không tìm thấy file chứa khoá");
			return false;
		}
		try {
			fos.write(sKeyEncoded);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			JOptionPane.showMessageDialog(this.gui, "Tạo khoá PBE: Không thành công");
			return false;
		}
		try {
			fos.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			JOptionPane.showMessageDialog(this.gui, "Tạo khoá PBE: IOException");
			return false;
		}
		return true;

	}

	public String encryption(String algorithmName, String keyPath, String original, byte[] salt, int iterationCount) {
		File f = new File(keyPath);
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(f);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Mã hoá PBE: Không tìm tấy file chứa khoá");
		}
		byte[] keyBytes = new byte[(int) f.length()];
		try {
			fis.read(keyBytes);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Mã hoá PBE: IOException");
		}

		byte[] plainText = original.getBytes();
		try {
			pbeCipher = Cipher.getInstance(algorithmName);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Mã hoá PBE: Thuật toán hiện tại không được hỗ trợ");
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Mã hoá PBE: Mode và Padding không hỗ trợ với thuật toán này");
		}
		SecretKeyFactory keyFactory = null;
		try {
			keyFactory = SecretKeyFactory.getInstance(algorithmName);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Mã hoá PBE: Thuật toán hiện tại không được hỗ trợ");
		}
		// Create PBE parameter set with SALT and COUNTER
		AlgorithmParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount);
		PBEKeySpec pbeKeySpec = new PBEKeySpec(new String(keyBytes).toCharArray());
		SecretKey key = null;
		try {
			key = keyFactory.generateSecret(pbeKeySpec);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Mã hoá PBE: Không thành công");
		}
		// Create PBE Cipherby
		try {
			pbeCipher.init(Cipher.ENCRYPT_MODE, key, pbeParamSpec);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Mã hoá PBE: Khoá không hợp lệ");
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Mã hoá PBE: Tham số thuật toán không hợp lệ");
		}
		byte[] encryptedContent = null;
		try {
			encryptedContent = pbeCipher.doFinal(plainText);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Mã hoá PBE: Không thành công");
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Mã hoá PBE: Không thành công");
		}
		String result = encoder.encodeToString(encryptedContent);
		return result;
	}

	public String decryption(String algorithmName, String keyPath, String cipherString, byte[] salt,
			int iterationCount) {
		File fKey = new File(keyPath);
		FileInputStream fos = null;
		try {
			fos = new FileInputStream(fKey);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Giải mã PBE: Không tìm thấy file chứa khoá");
		}
		byte[] keyBytes = new byte[(int) fKey.length()];
		try {
			fos.read(keyBytes);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Giải mã PBE: IOException");
		}

		byte[] cipherText = decoder.decode(cipherString);

		SecretKeyFactory keyFactory = null;
		try {
			keyFactory = SecretKeyFactory.getInstance(algorithmName);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Giải mã PBE: Thuật toán này không tồn tại");
		}
		PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount,
				new IvParameterSpec(pbeCipher.getIV()));
		PBEKeySpec pbeKeySpec = new PBEKeySpec(new String(keyBytes).toCharArray());
		SecretKey sKey = null;
		try {
			sKey = keyFactory.generateSecret(pbeKeySpec);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Giải mã PBE: Không thành công");
		}
		try {
			pbeCipher.init(Cipher.DECRYPT_MODE, sKey, pbeParamSpec);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Giải mã PBE: Khoá không hợp lệ");
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Giải mã PBE: Tham số thuật toán không hợp lệ");
		}
		byte[] plainText = null;
		try {
			plainText = pbeCipher.doFinal(cipherText);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Giải mã PBE: Không thành công");
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Giải mã PBE: Không thành công");
		}
		String result = null;
		try {
			result = new String(plainText, UNICODE_FORMAT);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			JOptionPane.showMessageDialog(this.gui, "Giải mã PBE: Kiểu encode không hỗ trợ");
			e.printStackTrace();
		}
		return result;
	}

}
