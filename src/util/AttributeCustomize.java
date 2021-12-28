package util;

import java.util.Arrays;

public class AttributeCustomize {
	Object[] modes;
	Object[] paddings;
	Object[] keySizes;

	public AttributeCustomize() {
		this.modes = null;
		this.paddings = null;
		this.keySizes = null;
	}

	public AttributeCustomize(Object[] modes, Object[] paddings, Object[] keySizes) {
		super();

		this.modes = modes;
		this.paddings = paddings;
		this.keySizes = keySizes;

	}

	public Object[] getMode() {
		return modes;
	}

	public void setMode(Object[] mode) {
		this.modes = mode;
	}

	public Object[] getPadding() {
		return paddings;
	}

	public void setPadding(Object[] paddings) {
		this.paddings = paddings;
	}

	public Object[] getKeySizes() {
		return keySizes;
	}

	public void setKeySizes(Object[] keySizes) {
		this.keySizes = keySizes;
	}

	@Override
	public String toString() {
		return "AttributeCustomize [modes=" + Arrays.toString(modes) + ", paddings=" + Arrays.toString(paddings)
				+ ", keySizes=" + Arrays.toString(keySizes) + "]";
	}

}
