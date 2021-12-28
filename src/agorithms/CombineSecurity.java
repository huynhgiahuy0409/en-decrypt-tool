package agorithms;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;

import org.apache.commons.lang3.StringUtils;

import gui.GUI;
import model.AsymmetricAlgorithm;
import model.SymmetricAlgorithm;
import util.Constant;
import util.FileUtils;

public class CombineSecurity {
	private GUI gui;

	public CombineSecurity(GUI gui) {
		super();
		this.gui = gui;
	}

	public String encryptionRSAWithSym(String publicKeyPath, SymmetricAlgorithm sAlgo, AsymmetricAlgorithm asAlgo,
			String plainPath) throws IOException, IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException {
		if (StringUtils.isEmpty(publicKeyPath) || StringUtils.isEmpty(plainPath)) {
			JOptionPane.showMessageDialog(this.gui, "Đường dãn không được bỏ trống");
			return null;
		}
		/* ___GENERATIVE S-KEY___ */
		KeyGenerator keyGenerator = null;
		keyGenerator = KeyGenerator.getInstance(sAlgo.getAlgorithmName());
		SecretKey sKey = keyGenerator.generateKey();
		byte[] symKeyBytes = sKey.getEncoded();
		/* ___Get PUBLIC KEY FROM PATH___ */
		PublicKey publicKey = null;
		publicKey = this.getPublicKeyFromPath(publicKeyPath, asAlgo);
		/*------*/
		String outputPath = FileUtils.processPath(plainPath, Constant.ENCRYPT_PREFIX);
		File outputFile = new File(outputPath);
		FileOutputStream outputFos = new FileOutputStream(outputFile);
		DataOutputStream outputDos = new DataOutputStream(outputFos);
		/* ___SETUP AS-CIPHER___ */
		String asAlgorithm = asAlgo.getAlgorithmName();
		String asMode = asAlgo.getMode();
		String asPadding = asAlgo.getPadding();
		Cipher asCipher = null;
		if (asMode.equals("None") && asPadding.equals("None")) {
			asCipher = Cipher.getInstance(asAlgorithm);
		} else {
			asCipher = Cipher.getInstance(asAlgorithm + "/" + asMode + "/" + asPadding);
		}
		try {
			asCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		} catch (InvalidKeyException e) {
			JOptionPane.showMessageDialog(this.gui, "Khoá không hợp lệ");
		}
		/* ENCRYPT S-KEY */
		byte[] asCipherText;
		asCipherText = asCipher.doFinal(symKeyBytes);
		/* SAVE SIZE & ENCRYPTED SYMMETRIC KEY */
		outputDos.writeUTF(String.valueOf(asCipherText.length));
		outputDos.write(asCipherText);
		/* ___SETUP S-CIPHER___ */
		String sAlgorithm = sAlgo.getAlgorithmName();
		String sMode = sAlgo.getMode();
		String sPadding = sAlgo.getPadding();
		Cipher sCipher = null;
		byte[] iv = null;
		if (sMode.equals("None") && sPadding.equals("None")) {
			sCipher = Cipher.getInstance(sAlgorithm);
		} else {
			sCipher = Cipher.getInstance(sAlgorithm + "/" + sMode + "/" + sPadding);
		}
		try {
			sCipher.init(Cipher.ENCRYPT_MODE, sKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			JOptionPane.showMessageDialog(this.gui, "Khoá không hợp lệ");
		}
		if (!sMode.equals("ECB")) {
			iv = sCipher.getIV();
			outputDos.writeUTF(String.valueOf(iv.length));
			outputDos.write(iv);
		}
		/* READ INPUT DATA */
		File inputDataFile = new File(plainPath);
		FileInputStream inputDataFis = new FileInputStream(inputDataFile);
		byte[] sPlainText = new byte[(int) inputDataFile.length()];
		inputDataFis.read(sPlainText);
		/* ENCRYPTED INPUT DATA BY SYMMETRIC */
		byte[] sCipherText = sCipher.doFinal(sPlainText);
		outputDos.writeUTF(String.valueOf(sCipherText.length));
		outputDos.write(sCipherText);
		outputDos.flush();
		return outputFile.getAbsolutePath();
	}

	public String decryptionRSAWithSym(String privateKeyPath, SymmetricAlgorithm sAlgo, AsymmetricAlgorithm asAlgo,
			String cipherPath) {
		if (StringUtils.isEmpty(privateKeyPath) || StringUtils.isEmpty(cipherPath)) {
			JOptionPane.showMessageDialog(this.gui, "Đường dãn không được bỏ trống");
			return null;
		}
		try {
			/* ___Get PUBLIC KEY FROM PATH___ */
			PrivateKey privateKey = this.getPrivateKeyFromPath(privateKeyPath, asAlgo);
			/* ___SETUP AS-CIPHER___ */
			String asAlgorithm = asAlgo.getAlgorithmName();
			String asMode = asAlgo.getMode();
			String asPadding = asAlgo.getPadding();
			String sAlgorithm = sAlgo.getAlgorithmName();
			String sMode = sAlgo.getMode();
			String sPadding = sAlgo.getPadding();
			Cipher asCipher = null;
			byte[] iv = null;
			if (asMode.equals("None") && asPadding.equals("None")) {
				asCipher = Cipher.getInstance(asAlgorithm);
			} else {
				asCipher = Cipher.getInstance(asAlgorithm + "/" + asMode + "/" + asPadding);
			}
			asCipher.init(Cipher.DECRYPT_MODE, privateKey);
			/*------*/
			File cipherFile = new File(cipherPath);
			FileInputStream cipherFis = new FileInputStream(cipherFile);
			DataInputStream cipherDis = new DataInputStream(cipherFis);
			/* ___GET CIPHER-SKEY___ */
			String asCipherLength = cipherDis.readUTF();
			byte[] asCipherText = new byte[Integer.valueOf(asCipherLength)];
			cipherDis.read(asCipherText);
			/* ___GET IV___ */
			if (!sMode.equals("ECB")) {
				String ivLength = cipherDis.readUTF();
				iv = new byte[Integer.valueOf(ivLength)];
				cipherDis.read(iv);
			}
			/* ___GET CIPHER TEXT___ */
			String sCipherLength = cipherDis.readUTF();
			byte[] sCipherText = new byte[Integer.valueOf(sCipherLength)];
			cipherDis.read(sCipherText);
			cipherDis.close();
			byte[] asPlainText = asCipher.doFinal(asCipherText);
			SecretKeySpec sks = new SecretKeySpec(asPlainText, sAlgo.getAlgorithmName());
			/* ___SETUP S-CIPHER___ */
			Cipher sCipher = null;
			if (sMode.equals("None") && sPadding.equals("None")) {
				sCipher = Cipher.getInstance(sAlgorithm);
			} else {
				sCipher = Cipher.getInstance(sAlgorithm + "/" + sMode + "/" + sPadding);
			}
			if (iv != null) {
				sCipher.init(Cipher.DECRYPT_MODE, sks, new IvParameterSpec(iv));
			} else {
				sCipher.init(Cipher.DECRYPT_MODE, sks);
			}
			byte[] sPlainText = sCipher.doFinal(sCipherText);
			String plainPath = FileUtils.processPath(cipherPath, Constant.DECRYPT_PREFIX);
			File plainFile = new File(plainPath);
			FileOutputStream plainFos = new FileOutputStream(plainFile);
			plainFos.write(sPlainText);
			plainFos.close();
			return plainFile.getAbsolutePath();

		} catch (Exception e) {
			JOptionPane.showMessageDialog(this.gui, "Không thành công");
			return null;
		}
	}

	private PublicKey getPublicKeyFromPath(String keyPath, AsymmetricAlgorithm asymmetricAlgorithm)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		PublicKey result = null;
		KeyFactory kf = null;
		File keyFile = new File(keyPath);
		if (keyFile.exists() && keyFile.isFile()) {
			byte[] keyBytes = new byte[(int) keyFile.length()];
			FileInputStream publicKeyFis = new FileInputStream(keyFile);
			publicKeyFis.read(keyBytes);
			kf = KeyFactory.getInstance(asymmetricAlgorithm.getAlgorithmName());
			result = kf.generatePublic(new X509EncodedKeySpec(keyBytes));
		}
		return result;
	}

	private PrivateKey getPrivateKeyFromPath(String keyPath, AsymmetricAlgorithm asymmetricAlgorithm)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		PrivateKey result = null;
		KeyFactory kf = null;
		File keyFile = new File(keyPath);
		if (keyFile.exists() && keyFile.isFile()) {
			byte[] keyBytes = new byte[(int) keyFile.length()];
			FileInputStream publicKeyFis = new FileInputStream(keyFile);
			publicKeyFis.read(keyBytes);
			kf = KeyFactory.getInstance(asymmetricAlgorithm.getAlgorithmName());
			result = kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
		}
		return result;
	}

}
