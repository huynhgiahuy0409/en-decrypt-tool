package agorithms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

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
import model.SymmetricAlgorithm;
import util.Constant;

public class SymmetricSecurity {
	private GUI gui;

	public SymmetricSecurity(GUI gui) {
		super();
		this.gui = gui;
	}

	public boolean generateKey(String algorithmName, int size, String destPath) throws IOException {
		if (StringUtils.isEmpty(destPath)) {
			JOptionPane.showMessageDialog(this.gui, "Đường dãn không được bỏ trống");
			return false;
		}
		KeyGenerator keyGenerator = null;
		try {
			keyGenerator = KeyGenerator.getInstance(algorithmName);
		} catch (NoSuchAlgorithmException e) {
			JOptionPane.showMessageDialog(this.gui, "Thuật toán hiện tại không được hỗ trợ");
			return false;
		}
		if (size != -1) {
			keyGenerator.init(size);
		}
		SecretKey secretKey = keyGenerator.generateKey();
		byte[] keyBytes = secretKey.getEncoded();
		File destDir = new File(destPath);

		if (destDir.exists() && destDir.isDirectory()) {
			destDir = new File(destPath + "\\" + Constant.PUBLIC_KEY_FILE_NAME);
		}
		FileOutputStream fos = null;
		fos = new FileOutputStream(destDir);
		fos.write(keyBytes);
		fos.flush();
		fos.close();
		return true;
	}

	public String encrypt(String originalStringOrPath, String keyPath, SymmetricAlgorithm sAlgo, String option)
			throws UnsupportedEncodingException, IOException {
		if (StringUtils.isEmpty(keyPath)) {
			JOptionPane.showMessageDialog(this.gui, "Đường dãn không được bỏ trống");
			return null;
		}
		String algorithmName = sAlgo.getAlgorithmName();
		String mode = sAlgo.getMode();
		String padding = sAlgo.getPadding();
		/* ____ READ KEY ____ */
		SecretKeySpec sks = null;
		sks = new SecretKeySpec(this.readKey(keyPath), algorithmName);
		/* ___ SETUP CIPHER ___ */
		Cipher cipher = this.getCipherInstance(this.gui, algorithmName, mode, padding);
		byte[] iv = null;
		try {
			cipher.init(Cipher.ENCRYPT_MODE, sks);
			iv = cipher.getIV();
		} catch (InvalidKeyException e) {
			JOptionPane.showMessageDialog(this.gui, "Khoá không hợp lệ");
		}
		byte[] plainText = null;
		byte[] cipherText = null;
		byte[] mainCipherText = null;
		String result = null;
		/* ____ ENCRYPT TEXT ____ */
		if (option.equals(Constant.TEXT_TYPE)) {
			plainText = originalStringOrPath.getBytes(Constant.UNICODE_FORMAT);
			try {
				cipherText = cipher.doFinal(plainText);
				mainCipherText = this.writeMainCipherText(iv, cipherText);
				result = Constant.encoder.encodeToString(mainCipherText);
			} catch (IllegalBlockSizeException e) {
				JOptionPane.showMessageDialog(this.gui, "Không thành công");
			} catch (BadPaddingException e) {
				JOptionPane.showMessageDialog(this.gui, "Không thành công");
			}
			/* ___ ENCRYPT FILE ___ */
		} else if (option.equals(Constant.FILE_TYPE)) {
			if (StringUtils.isEmpty(originalStringOrPath)) {
				JOptionPane.showMessageDialog(this.gui, "Đường dãn không được bỏ trống");
				return null;
			}
			plainText = this.readInputFile(originalStringOrPath);
			try {
				cipherText = cipher.doFinal(plainText);
			} catch (IllegalBlockSizeException e) {
				JOptionPane.showMessageDialog(this.gui, "Không thành công");
			} catch (BadPaddingException e) {
				JOptionPane.showMessageDialog(this.gui, "Không thành công");
			}
			String cipherPath = this.processPath(originalStringOrPath, Constant.ENCRYPT_PREFIX);
			result = this.writeMainCipherFile(cipherPath, iv, cipherText);
		}
		return result;
	}

	public String decrypt(String cipherStringOrPath, String keyPath, SymmetricAlgorithm sAlgo, String option)
			throws IOException {
		if (StringUtils.isEmpty(keyPath)) {
			JOptionPane.showMessageDialog(this.gui, "Đường dãn không được bỏ trống");
			return null;
		}
		String algorithmName = sAlgo.getAlgorithmName();
		String mode = sAlgo.getMode();
		String padding = sAlgo.getPadding();
		SecretKeySpec sks = new SecretKeySpec(this.readKey(keyPath), algorithmName);
		/* ___ SETUP CIPHER ___ */
		Cipher cipher = this.getCipherInstance(this.gui, algorithmName, mode, padding);
		/* ___DECRYPT TEXT ___ */
		byte[] mainCipherText = null;
		byte[] cipherText = null;
		byte[] plainText = null;
		byte[] iv = null;
		String result = null;
		if (option.equals(Constant.TEXT_TYPE)) {
			mainCipherText = Constant.decoder.decode(cipherStringOrPath);
			byte[][] ivAndCipherText = this.readMainCipherText(mainCipherText);
			iv = ivAndCipherText[0];
			cipherText = ivAndCipherText[1];
			/* ___CHECK MODE AND PADDING TO SET IV___ */
			if (mode.equals("ECB")) {
				try {
					cipher.init(Cipher.DECRYPT_MODE, sks);
				} catch (InvalidKeyException e) {
					JOptionPane.showMessageDialog(this.gui, "Khoá không hợp lệ");
				}
			} else {
				try {
					cipher.init(Cipher.DECRYPT_MODE, sks, new IvParameterSpec(iv));
				} catch (InvalidKeyException e) {
					JOptionPane.showMessageDialog(this.gui, "Khoá không hợp lệ");
				} catch (InvalidAlgorithmParameterException e) {
					JOptionPane.showMessageDialog(this.gui, "Sai tham số đầu vào");
				}
			}
			try {
				plainText = cipher.doFinal(cipherText);
			} catch (IllegalBlockSizeException e1) {
				e1.printStackTrace();
				JOptionPane.showMessageDialog(this.gui, "Không thành công");
			} catch (BadPaddingException e1) {
				e1.printStackTrace();
				JOptionPane.showMessageDialog(this.gui, "Không thành công");
			}
			result = new String(plainText, Constant.UNICODE_FORMAT);
		} else if (option.equals(Constant.FILE_TYPE)) {
			byte[][] ivAndCipherText = this.readMainCipherFile(cipherStringOrPath);
			iv = ivAndCipherText[0];
			cipherText = ivAndCipherText[1];
			/* ___CHECK MODE AND PADDING TO SET IV___ */
			if (mode.equals("ECB")) {
				try {
					cipher.init(Cipher.DECRYPT_MODE, sks);
				} catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					JOptionPane.showMessageDialog(this.gui, "Khoá không hợp lệ");
				}
			} else {
				try {
					cipher.init(Cipher.DECRYPT_MODE, sks, new IvParameterSpec(iv));
				} catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					JOptionPane.showMessageDialog(this.gui, "Khoá không hợp lệ");
				} catch (InvalidAlgorithmParameterException e) {
					// TODO Auto-generated catch block
					JOptionPane.showMessageDialog(this.gui, "Sai tham số đầu vào");
				}
			}
			try {
				plainText = cipher.doFinal(cipherText);
			} catch (IllegalBlockSizeException e1) {
				e1.printStackTrace();
				JOptionPane.showMessageDialog(this.gui, "Không thành công");
			} catch (BadPaddingException e1) {
				e1.printStackTrace();
				JOptionPane.showMessageDialog(this.gui, "Không thành công");
			}
			String decyptedPath = this.processPath(cipherStringOrPath, Constant.DECRYPT_PREFIX);
			result = this.writeOutputFile(decyptedPath, plainText);
		}
		return result;
	}

	private Cipher getCipherInstance(GUI gui, String algorithmName, String mode, String padding) {
		Cipher cipher = null;
		try {
			if (mode.equals(Constant.DEFAULT_SELECTION) && padding.equals(Constant.DEFAULT_SELECTION)) {
				cipher = Cipher.getInstance(algorithmName);
			} else {
				cipher = Cipher.getInstance(algorithmName + "/" + mode + "/" + padding);
			}
		} catch (NoSuchAlgorithmException e) {
			JOptionPane.showMessageDialog(gui, e.getMessage() + "");
		} catch (NoSuchPaddingException e) {
			JOptionPane.showMessageDialog(gui, e.getMessage() + "");
		}
		return cipher;
	}

	private String processPath(String path, String prefix) {
		File f = new File(path);
		String fileName = f.getName();
		String parentPath = f.getParent();
		int lastIndexOfPoit = fileName.lastIndexOf(".");
		String suffix = fileName.substring(lastIndexOfPoit);
		StringBuilder sb = new StringBuilder(parentPath);
		sb.append("\\");
		sb.append(prefix);
		sb.append(suffix);
		return sb.toString();
	}

	private byte[] readKey(String keyPath) throws IOException {
		File keyFile = new File(keyPath);
		FileInputStream keyFis = new FileInputStream(keyFile);
		byte[] keyBytes = new byte[(int) keyFile.length()];
		keyFis.read(keyBytes);
		keyFis.close();
		return keyBytes;
	}

	/* Dùng để đọc file dữ liệu đầu vào */
	private byte[] readInputFile(String inputPath) throws IOException {
		File inputFile = new File(inputPath);
		FileInputStream inputFis = new FileInputStream(inputFile);
		byte[] plainText = new byte[(int) inputFile.length()];
		inputFis.read(plainText);
		inputFis.close();
		return plainText;
	}

	/* Dùng để lưu dữ liệu vào 1 file */
	private String writeOutputFile(String outputPath, byte[] data) throws IOException {
		File outputFile = new File(outputPath);
		if (!outputFile.exists()) {
			outputFile.createNewFile();
		}
		FileOutputStream fos = new FileOutputStream(outputFile);
		fos.write(data);
		fos.flush();
		fos.close();
		return outputFile.getAbsolutePath();
	}

	private byte[] writeMainCipherText(byte[] iv, byte[] cipherText) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		dos.writeUTF(String.valueOf(iv.length));
		dos.write(iv);
		dos.writeUTF(String.valueOf(cipherText.length));
		dos.write(cipherText);
		dos.flush();
		return baos.toByteArray();
	}

	private byte[][] readMainCipherText(byte[] mainCipherText) throws IOException {
		ByteArrayInputStream bais = new ByteArrayInputStream(mainCipherText);
		DataInputStream dis = new DataInputStream(bais);
		byte[] iv = new byte[Integer.valueOf(dis.readUTF())];
		dis.read(iv);
		byte[] cipherText = new byte[Integer.valueOf(dis.readUTF())];
		dis.read(cipherText);
		bais.close();
		dis.close();
		return new byte[][] { iv, cipherText };
	}

	private String writeMainCipherFile(String path, byte[] iv, byte[] cipherText) throws IOException {
		File cipherFile = new File(path);
		if (!cipherFile.exists()) {
			cipherFile.createNewFile();
		}
		FileOutputStream cipherFos = new FileOutputStream(cipherFile);
		DataOutputStream cipherDos = new DataOutputStream(cipherFos);
		cipherDos.writeUTF(String.valueOf(iv.length));
		cipherDos.write(iv);
		cipherDos.writeUTF(String.valueOf(cipherText.length));
		cipherDos.write(cipherText);
		cipherDos.flush();
		cipherFos.close();
		cipherDos.close();
		return cipherFile.getAbsolutePath();
	}

	private byte[][] readMainCipherFile(String mainCipherPath) throws NumberFormatException, IOException {
		File mainCipherFile = new File(mainCipherPath);
		FileInputStream mainCipherFis = new FileInputStream(mainCipherFile);
		DataInputStream mainCipherDos = new DataInputStream(mainCipherFis);
		byte[] iv = new byte[Integer.valueOf(mainCipherDos.readUTF())];
		mainCipherDos.read(iv);
		byte[] mainCipherText = new byte[Integer.valueOf(mainCipherDos.readUTF())];
		mainCipherDos.read(mainCipherText);
		mainCipherDos.close();
		return new byte[][] { iv, mainCipherText };
	}

	public static void main(String[] args) {
		SymmetricSecurity ins = new SymmetricSecurity(null);
	}
}
