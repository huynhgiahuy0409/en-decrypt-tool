package util;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class ServiceCustomize {
	Map<String, AttributeCustomize> service = new HashMap<String, AttributeCustomize>();
	KeySizeProcess keySizeProcess = new KeySizeProcess();

	public ServiceCustomize() {
		for (Provider provider : Security.getProviders()) {
			for (Provider.Service s : provider.getServices()) {
				if (s.getType().equals("Cipher")) {
					Object[] modes = new Object[] {};
					Object[] paddings = new Object[] {};
					Object[] keySizes = new Object[] {};
					String algorithmNameFromProvider = s.getAlgorithm();
					String[] algorithmNameSeparates = algorithmNameFromProvider.split("/");
					String mainAlgorithmName = algorithmNameSeparates[0];
					final String SUPPORDTED_MODES = s.getAttribute("SupportedModes");
					final String SUPPORDTED_PADDINGS = s.getAttribute("SupportedPaddings");
					AttributeCustomize attributeInstance;
					modes = this.appendValue(modes, "None");
					paddings = this.appendValue(paddings, "None");
					keySizes = this.appendValue(keySizes, "None");

					if (!service.containsKey(mainAlgorithmName)) {
						if (algorithmNameSeparates.length == 1) {
							/* Setup MODE */
							if (SUPPORDTED_MODES != null) {
								Object[] supportedModes = this.separate(SUPPORDTED_MODES, "|");
								modes = this.appendValues(modes, supportedModes);
							}
							/* Setup PADDING */
							if (SUPPORDTED_PADDINGS != null) {
								Object[] supportedPaddings = this.separate(SUPPORDTED_PADDINGS, "|");
								paddings = this.appendValues(paddings, supportedPaddings);
							}
						} else if (algorithmNameSeparates.length == 3) {
							modes = this.appendValue(modes, algorithmNameSeparates[1]);
							paddings = this.appendValue(paddings, algorithmNameSeparates[2]);
						}
						/* Setup KEY-SIZE */
						Object[] processedKeySizes = keySizeProcess.process(algorithmNameFromProvider);
						if (processedKeySizes != null) {
							keySizes = this.appendValues(keySizes, processedKeySizes);
						}
						attributeInstance = new AttributeCustomize(modes, paddings, keySizes);
						service.put(mainAlgorithmName, attributeInstance);
					} else {
						AttributeCustomize existAttribute = service.get(mainAlgorithmName);
						Object[] exModes = existAttribute.getMode();
						Object[] exPaddings = existAttribute.getPadding();
						if (algorithmNameSeparates.length == 1) {
							if (SUPPORDTED_MODES != null) {
								Object[] supportedModes = this.separate(SUPPORDTED_MODES, "|");
								modes = this.checkValues(exModes, supportedModes);
							}
							/* Setup PADDING */
							if (SUPPORDTED_PADDINGS != null) {
								Object[] supportedPaddings = this.separate(SUPPORDTED_PADDINGS, "|");
								paddings = this.checkValues(exPaddings, supportedPaddings);
							}
						} else if (algorithmNameSeparates.length == 3) {
							modes = this.checkValue(exModes, algorithmNameSeparates[1]);
							paddings = this.checkValue(exPaddings, algorithmNameSeparates[2]);
						}
						existAttribute.setMode(modes);
						existAttribute.setPadding(paddings);
						service.put(mainAlgorithmName, existAttribute);
					}
				}
			}
		}
	}

	private Object[] appendValue(Object[] objs, Object newObj) {
		ArrayList<Object> temp = new ArrayList<Object>(Arrays.asList(objs));
		temp.add(newObj);
		return temp.toArray();
	}

	private Object[] appendValues(Object[] objs, Object[] newObjs) {
		ArrayList<Object> objList = new ArrayList<Object>(Arrays.asList(objs));
		ArrayList<Object> newObjList = new ArrayList<Object>(Arrays.asList(newObjs));
		for (Object object : newObjList) {
			objList.add(object);
		}
		return objList.toArray();
	}

	private Object[] checkValue(Object[] exValue, Object newValue) {
		ArrayList<Object> exValueList = new ArrayList<Object>(Arrays.asList(exValue));
		if (!exValueList.contains(newValue)) {
			exValueList.add(newValue);
		}
		return exValueList.toArray();
	}

	private Object[] checkValues(Object[] exValue, Object[] newValues) {
		ArrayList<Object> exValueList = new ArrayList<Object>(Arrays.asList(exValue));
		ArrayList<Object> newExValueList = new ArrayList<Object>(Arrays.asList(newValues));

		newExValueList.forEach(newValue -> {
			if (!exValueList.contains(newValue)) {
				exValueList.add(newValue);
			}
		});
		return exValueList.toArray();
	}

	private String[] separate(String value, String sourceRegex) {
		if (value != null) {
			String newRegex = "=";
			String standardValue = value.replace(sourceRegex, newRegex);
			String[] result = standardValue.split(newRegex);
			return result;
		}
		return null;
	}

	public Map<String, AttributeCustomize> getSerivce() {
		return service;
	}

}
