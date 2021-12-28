package util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JOptionPane;

import gui.GUI;

public class FileUtils {
	public static byte[] readKey(String keyPath) throws IOException {
		File keyFile = new File(keyPath);
		FileInputStream keyFis = new FileInputStream(keyFile);
		byte[] keyBytes = new byte[(int) keyFile.length()];
		keyFis.read(keyBytes);
		keyFis.close();
		return keyBytes;
	}

	public static Cipher getCipherInstance(GUI gui, String algorithmName, String mode, String padding) {
		Cipher cipher = null;
		try {
			if (mode.equals(Constant.DEFAULT_SELECTION) && padding.equals(Constant.DEFAULT_SELECTION)) {
				cipher = Cipher.getInstance(algorithmName);
			} else {
				cipher = Cipher.getInstance(algorithmName + "/" + mode + "/" + padding);
			}
		} catch (NoSuchAlgorithmException e) {
			JOptionPane.showMessageDialog(gui, e.getMessage());
		} catch (NoSuchPaddingException e) {
			JOptionPane.showMessageDialog(gui, e.getMessage());
		}
		return cipher;
	}

	public byte[] checkModeToGetIV(Cipher cipher, String mode) {
		byte[] result = null;
		if (!mode.equals("ECB")) {
			result = cipher.getIV();
		}
		return result;
	}

	public static String processPath(String path, String prefix) {
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
}
