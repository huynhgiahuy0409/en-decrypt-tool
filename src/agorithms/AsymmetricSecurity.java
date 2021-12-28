package agorithms;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.swing.JOptionPane;

import org.apache.commons.lang3.StringUtils;

import gui.GUI;
import model.AsymmetricAlgorithm;
import util.Constant;
import util.FileUtils;

public class AsymmetricSecurity {
	private GUI gui;

	public AsymmetricSecurity(GUI gui) {
		super();
		this.gui = gui;
	}

	public boolean generativeKeyPair(String algorithm, int keySize, String publicKeyPath, String privateKeyPath) {
		if (StringUtils.isEmpty(publicKeyPath) && StringUtils.isEmpty(privateKeyPath)) {
			JOptionPane.showMessageDialog(this.gui, "Đường dãn không được bỏ trống");
			return false;
		}
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
			if (keySize != -1) {
				keyPairGenerator.initialize(keySize);
			}
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			byte[] publicKeyEncoded = publicKey.getEncoded();
			byte[] privateKeyEncoded = privateKey.getEncoded();
			File publicKeyFile = new File(publicKeyPath + "\\" + Constant.PUBLIC_KEY_FILE_NAME);
			File privateKeyFile = new File(privateKeyPath + "\\" + Constant.PRIVATE_KEY_FILE_NAME);
			if (!publicKeyFile.exists()) {
				publicKeyFile.createNewFile();
			}
			if (!privateKeyFile.exists()) {
				privateKeyFile.createNewFile();
			}
			FileOutputStream publicKeyFos = new FileOutputStream(publicKeyFile);
			FileOutputStream privateKeyFos = new FileOutputStream(privateKeyFile);
			publicKeyFos.write(publicKeyEncoded);
			privateKeyFos.write(privateKeyEncoded);
			publicKeyFos.close();
			privateKeyFos.close();
			return true;

		} catch (Exception e) {
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Tạo khoá không thành công");
			return false;
		}
	}

	public String encryption(String originalOrOriginalPath, String publicKeyPath, AsymmetricAlgorithm asAlgo,
			String option) throws IOException {
		if (StringUtils.isEmpty(publicKeyPath)) {
			JOptionPane.showMessageDialog(this.gui, "Đường dãn không được bỏ trống");
			return null;
		}
		String algorithmName = asAlgo.getAlgorithmName();
		String mode = asAlgo.getMode();
		String padding = asAlgo.getPadding();
		/* ___READ KEY___ */
		byte[] keyBytes = FileUtils.readKey(publicKeyPath);
		/* ___SETUP KEY___ */
		KeyFactory kf = null;
		PublicKey publicKey = null;
		try {
			kf = KeyFactory.getInstance(algorithmName);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Thuật toán hiện tại không được hỗ trợ");
		}
		try {
			publicKey = kf.generatePublic(new X509EncodedKeySpec(keyBytes));
		} catch (InvalidKeySpecException e) {
			JOptionPane.showMessageDialog(this.gui, "Khoá không hợp lệ");
		}

		Cipher cipher = FileUtils.getCipherInstance(this.gui, algorithmName, mode, padding);
		try {
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		} catch (InvalidKeyException e1) {
			// TODO Auto-generated catch block
			JOptionPane.showMessageDialog(this.gui, "Khoá không hợp lệ");
		}
		byte[] cipherText = null;
		byte[] plainText = null;
		String result = null;
		/* ___ENCRYPT TEXT___ */
		if (option.equals(Constant.TEXT_TYPE)) {
			plainText = originalOrOriginalPath.getBytes(Constant.UNICODE_FORMAT);
			try {
				cipherText = cipher.doFinal(plainText);
				return result = Constant.encoder.encodeToString(cipherText);
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				JOptionPane.showMessageDialog(this.gui, " Không thành công");
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				JOptionPane.showMessageDialog(this.gui, "Không thành công");
			}
		}
		return null;
	}

	public String decryption(String cipherString, String privateKeyPath, AsymmetricAlgorithm asAlgo, String option)
			throws IOException {
		if (StringUtils.isEmpty(privateKeyPath)) {
			JOptionPane.showMessageDialog(this.gui, "Đường dãn không được bỏ trống");
			return null;
		}
		String algorithmName = asAlgo.getAlgorithmName();
		String mode = asAlgo.getMode();
		String padding = asAlgo.getPadding();
		byte[] keyBytes = FileUtils.readKey(privateKeyPath);
		KeyFactory kf = null;
		PrivateKey privateKey = null;
		try {
			kf = KeyFactory.getInstance(algorithmName);
		} catch (NoSuchAlgorithmException e) {
			JOptionPane.showMessageDialog(this.gui, "Thuật toán hiện tại không được hỗ trợ");
		}
		try {
			privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			JOptionPane.showMessageDialog(this.gui, "Khoá không hợp lệ");
		}
		Cipher cipher = FileUtils.getCipherInstance(this.gui, algorithmName, mode, padding);
		try {
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
		} catch (InvalidKeyException e) {
			JOptionPane.showMessageDialog(this.gui, "Khoá không hợp lệ");
		}
		byte[] cipherText = null;
		byte[] plainText = null;
		String result = null;
		if (option.equals(Constant.TEXT_TYPE)) {
			cipherText = Constant.decoder.decode(cipherString);
			try {
				plainText = cipher.doFinal(cipherText);
				return new String(plainText, Constant.UNICODE_FORMAT);
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				JOptionPane.showMessageDialog(this.gui, "Không thành công");
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				JOptionPane.showMessageDialog(this.gui, "Không thành công");
			}
		}
		return null;
	}

}
