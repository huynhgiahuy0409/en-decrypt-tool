package util;

import java.util.ArrayList;
import java.util.List;

public class KeySizeProcess {
	private Object[] determine(Object... value) {
		return value;
	}

	private Object[] range(Integer start, Integer end) {
		List<Object> result = new ArrayList<Object>();
		for (int i = start; i <= end; i++) {
			result.add(i);
		}
		return result.toArray();
	}

	private Object[] noRetriction() {
		List<Object> result = new ArrayList<Object>();
		return result.toArray();
	}

	private Object[] multipleOf8(Integer start, Integer end) {
		List<Object> result = new ArrayList<Object>();
		for (int i = start; i <= end; i++) {
			if (i % 8 == 0) {
				result.add(i);
			}
		}
		return result.toArray();
	}

	public Object[] process(String algorithmName) {
		switch (algorithmName) {
		case "AES":
			return determine(128, 192, 256);
		case "ARCFOUR":
			return range(40, 1024);
		case "Blowfish":
			return multipleOf8(32, 448);
		case "DES":
			return determine(56);
		case "RC2":
			return range(40, 1024);
		case "DESede":
			return determine(112, 168);
		case "RSA":
			return determine(1024, 2046, 3072, 4096);
		default:
		}
		if (algorithmName.startsWith("PBE")) {
			return null;
		}
		return null;
	}
}
