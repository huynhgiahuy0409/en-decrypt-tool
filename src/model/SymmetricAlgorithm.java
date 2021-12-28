package model;

public class SymmetricAlgorithm {
	private String algorithmName;
	private int keySize;
	private String mode;
	private String padding;

	public SymmetricAlgorithm(String algorithmName, int keySize, String mode, String padding) {
		super();
		this.algorithmName = algorithmName;
		this.keySize = keySize;
		this.mode = mode;
		this.padding = padding;
	}

	public SymmetricAlgorithm(String algorithmName, String mode, String padding) {
		super();
		this.algorithmName = algorithmName;
		this.mode = mode;
		this.padding = padding;
	}

	public SymmetricAlgorithm() {
		super();
	}

	public String getAlgorithmName() {
		return algorithmName;
	}

	public void setAlgorithmName(String algorithmName) {
		this.algorithmName = algorithmName;
	}

	public int getKeySize() {
		return keySize;
	}

	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}

	public String getMode() {
		return mode;
	}

	public void setMode(String mode) {
		this.mode = mode;
	}

	public String getPadding() {
		return padding;
	}

	public void setPadding(String padding) {
		this.padding = padding;
	}

}
