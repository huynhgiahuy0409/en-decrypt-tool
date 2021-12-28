package agorithms;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JOptionPane;

import gui.GUI;

public class HashSecurity {
	private GUI gui;

	public HashSecurity(GUI gui) {
		super();
		this.gui = gui;
	}

	public String checksum(String textOrFilePath, String algorithmName, String option) {
		MessageDigest md = null;
		byte[] hashTextBytes = null;
		try {
			md = MessageDigest.getInstance(algorithmName);
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			JOptionPane.showMessageDialog(this.gui, "Thuật toán hiện tại không được hỗ trợ");
		}
		if (option.equals("text")) {
			byte[] texts = textOrFilePath.getBytes();
			hashTextBytes = md.digest(texts);
			/* Convert to 16 */
		} else if (option.equals("file")) {
			File f = new File(textOrFilePath);
			FileInputStream fis = null;
			try {
				fis = new FileInputStream(f);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			DigestInputStream dis = new DigestInputStream(fis, md);
			byte[] buffer = new byte[(int) f.length()];
			try {
				dis.read(buffer);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			hashTextBytes = dis.getMessageDigest().digest();
		}
		/* Convert to 16 */
		BigInteger number = new BigInteger(1, hashTextBytes);
		String hashText = number.toString(16);
		return hashText;
	}

	public Object[] getHashAlgorithms() {
		List<Object> hashAlgorithmNames = new ArrayList<Object>();
		for (Provider provider : Security.getProviders()) {
			for (Provider.Service s : provider.getServices()) {
				if (s.getType().equals("MessageDigest")) {
					hashAlgorithmNames.add(s.getAlgorithm());
				}
			}
		}
		return hashAlgorithmNames.toArray();
	}
}
