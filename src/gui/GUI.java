package gui;

import java.awt.BorderLayout;
import java.awt.Button;
import java.awt.Color;
import java.awt.Component;
import java.awt.ComponentOrientation;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.SystemColor;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;

import org.apache.commons.lang3.StringUtils;

import agorithms.AsymmetricSecurity;
import agorithms.CombineSecurity;
import agorithms.HashSecurity;
import agorithms.PBESymmetricSecurity;
import agorithms.SymmetricSecurity;
import model.AsymmetricAlgorithm;
import model.SymmetricAlgorithm;
import util.AttributeCustomize;
import util.Constant;
import util.ServiceCustomize;

public class GUI extends JFrame {
	private JPanel contentPane;
	private final ButtonGroup selectBtnGroup = new ButtonGroup();
	private final ButtonGroup selectBtnGroupAsym = new ButtonGroup();
	private final ButtonGroup typeBtnGroup = new ButtonGroup();
	private final ButtonGroup typeBtnGroupAsym = new ButtonGroup();
	private final ButtonGroup typeBtnGroupHash = new ButtonGroup();
	private final JTabbedPane tabbedPane;
	private JTextField publicKeyTextField;
	private Button actionBtn;
	private JRadioButton encryptBtn;
	private JRadioButton decryptBtn;
	private JRadioButton encryptBtnAsym;
	private JRadioButton decryptBtnAsym;
	private JRadioButton encryptBtnCombine;
	private JRadioButton decryptBtnCombine;
	private JTextArea resultTextTextArea;
	private JTextArea originalTextTextArea;
	private JTextField originalFileTextField;
	private JTextField resultFileTextField;

	JFileChooser fileChooser = new JFileChooser();
	/* Inject */
	ServiceCustomize service = new ServiceCustomize();
	Map<String, AttributeCustomize> services = this.service.getSerivce();
	SymmetricSecurity symmetricSecurity = new SymmetricSecurity(this);
	PBESymmetricSecurity pbeAlgorithm = new PBESymmetricSecurity(this);
	AsymmetricSecurity asymmetricSecurity = new AsymmetricSecurity(this);
	HashSecurity hashAlgorithm = new HashSecurity(this);
	CombineSecurity combineSecurity = new CombineSecurity(this);
	private final ButtonGroup selectBtnGroupCombine = new ButtonGroup();

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					GUI gui = new GUI();
					gui.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	public GUI() {
		/* Setup */
		fileChooser.setFileSelectionMode(JFileChooser.CUSTOM_DIALOG);

		setDefaultCloseOperation(GUI.EXIT_ON_CLOSE);
		setBounds(100, 100, 1500, 600);

		JMenuBar menuBar = new JMenuBar();
		setJMenuBar(menuBar);
		JMenu fileMenu = new JMenu("File");
		menuBar.add(fileMenu);
		JMenu helpMenu = new JMenu("Help");
		menuBar.add(helpMenu);

		contentPane = new JPanel();
		contentPane.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);
		contentPane.setBackground(Color.WHITE);
		contentPane.setBorder(null);
		setContentPane(contentPane);
		contentPane.setLayout(new BorderLayout(0, 0));

		JPanel actionPanel = new JPanel();
		actionPanel.setBackground(Color.WHITE);
		contentPane.add(actionPanel, BorderLayout.SOUTH);
		actionPanel.setLayout(new BoxLayout(actionPanel, BoxLayout.X_AXIS));

		actionBtn = new Button("Generate Key");
		actionBtn.setForeground(Color.WHITE);
		actionBtn.setFont(new Font("Dialog", Font.BOLD, 16));
		actionBtn.setPreferredSize(new Dimension(300, 50));
		actionBtn.setBackground(SystemColor.textHighlight);
		actionPanel.add(actionBtn);

		tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		tabbedPane.setAutoscrolls(true);
		contentPane.add(tabbedPane, BorderLayout.CENTER);
		/*----------GENERATIVE KEY TAB----------*/
		this.showGenerativeKey();
		tabbedPane.setSelectedIndex(0);
		/*----------SYMMETRIC TAB----------*/
		this.showSymmetricInterface();
		/*----------ASYMMETRIC TAB----------*/
		this.showAsymmetricInterface();
		/*----------HASH TAB----------*/
		this.showCombineInterface();
		/*----------HASH TAB----------*/
		this.showHashInterface();
		tabbedPane.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent arg0) {
				int s = tabbedPane.getSelectedIndex();
				System.out.println(s);
				if (s == 0) {
					actionBtn.setLabel("Generate Key");
				} else if (s == 1) {
					encryptBtn.setSelected(true);
					if (encryptBtn.isSelected()) {
						actionBtn.setLabel("Encrypt");
					} else {
						actionBtn.setLabel("Decrypt");
					}
				} else if (s == 2) {
					encryptBtnAsym.setSelected(true);
					if (encryptBtnAsym.isSelected()) {
						actionBtn.setLabel("Encrypt");
					} else {
						actionBtn.setLabel("Decrypt");
					}
				} else if (s == 3) {
					encryptBtnCombine.setSelected(true);
					if (encryptBtnCombine.isSelected()) {
						actionBtn.setLabel("Encrypt");
					} else {
						actionBtn.setLabel("Decrypt");
					}
				} else if (s == 4) {
					actionBtn.setLabel("Run");
				}
			}
		});
	}

	private void showGenerativeKey() {
		JPanel genKeyPanel = new JPanel();
		tabbedPane.addTab("Generate Key", null, genKeyPanel, null);
		genKeyPanel.setLayout(new BorderLayout(0, 0));

		JPanel genKeyContentPanel = new JPanel();
		genKeyContentPanel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true), "Generative Key",
				TitledBorder.LEADING, TitledBorder.TOP, null, null));
		genKeyPanel.add(genKeyContentPanel, BorderLayout.CENTER);
		genKeyContentPanel.setLayout(new GridLayout(0, 1, 0, 0));

		JPanel selectionContentPanel = new JPanel();
		selectionContentPanel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true), "Select",
				TitledBorder.CENTER, TitledBorder.TOP, null, new Color(0, 0, 0)));
		genKeyContentPanel.add(selectionContentPanel);
		selectionContentPanel.setLayout(new GridLayout(1, 2, 0, 0));

		JPanel algorithmContainPanel = new JPanel();
		selectionContentPanel.add(algorithmContainPanel);
		algorithmContainPanel.setLayout(new GridLayout(3, 2, 20, 20));

		JLabel algorithmLabel = new JLabel("Algorithm");
		algorithmLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		algorithmLabel.setHorizontalTextPosition(SwingConstants.CENTER);
		algorithmLabel.setHorizontalAlignment(SwingConstants.CENTER);
		algorithmContainPanel.add(algorithmLabel);

		Map<String, AttributeCustomize> servicesKey = new HashMap<String, AttributeCustomize>();
		services.forEach((k, v) -> {
			if (!k.startsWith("PBE")) {
				servicesKey.put(k, v);
			}
		});
		JComboBox algorithmCombobox = new JComboBox(servicesKey.keySet().toArray());
		algorithmCombobox.setPreferredSize(new Dimension(400, 40));
		algorithmContainPanel.add(algorithmCombobox);

		JPanel keySizeContainPanel = new JPanel();
		keySizeContainPanel.setBorder(new LineBorder(new Color(0, 0, 0), 0, true));
		selectionContentPanel.add(keySizeContainPanel);
		keySizeContainPanel.setLayout(new GridLayout(3, 2, 20, 20));

		JLabel keySizeLabel = new JLabel("Key Size");
		keySizeLabel.setHorizontalTextPosition(SwingConstants.CENTER);
		keySizeLabel.setHorizontalAlignment(SwingConstants.CENTER);
		keySizeLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		keySizeContainPanel.add(keySizeLabel);

		JComboBox keySizeCombobox = new JComboBox();
		keySizeCombobox.setPreferredSize(new Dimension(400, 40));
		keySizeContainPanel.add(keySizeCombobox);

		JPanel keyPathContentPanel = new JPanel();
		keyPathContentPanel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true), "Store the key",
				TitledBorder.CENTER, TitledBorder.TOP, null, new Color(0, 0, 0)));
		genKeyContentPanel.add(keyPathContentPanel);
		keyPathContentPanel.setLayout(new GridLayout(3, 1, 0, 0));

		JPanel publicKeyPathContentPanel = new JPanel();
		publicKeyPathContentPanel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true),
				"Public Key Path", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		publicKeyPathContentPanel.setLayout(new BorderLayout(0, 0));

		publicKeyTextField = new JTextField();
		publicKeyTextField.setBackground(Color.WHITE);
		publicKeyTextField.setEditable(false);
		publicKeyTextField.setFont(new Font("Tahoma", Font.PLAIN, 16));
		publicKeyPathContentPanel.add(publicKeyTextField, BorderLayout.CENTER);
		publicKeyTextField.setColumns(10);
		JButton publicKeyBtn = new JButton("Browse");
		publicKeyBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser jsc = new JFileChooser();
				jsc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				int returnVal = jsc.showOpenDialog(null);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File f = jsc.getSelectedFile();
					publicKeyTextField.setText(f.getAbsolutePath());
				}
			}
		});
		publicKeyPathContentPanel.add(publicKeyBtn, BorderLayout.EAST);

		JPanel privateKeyPathContentPanel = new JPanel();
		privateKeyPathContentPanel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true),
				"Private Key Path", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		keyPathContentPanel.add(privateKeyPathContentPanel);
		privateKeyPathContentPanel.setLayout(new BorderLayout(0, 0));

		JTextField privateKeyTextField = new JTextField();
		privateKeyTextField.setFont(new Font("Tahoma", Font.PLAIN, 16));
		privateKeyPathContentPanel.add(privateKeyTextField, BorderLayout.CENTER);
		privateKeyTextField.setColumns(10);
		JButton privateKeyBtn = new JButton("Browse");
		privateKeyBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser jsc = new JFileChooser();
				jsc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				int returnVal = jsc.showOpenDialog(null);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File f = jsc.getSelectedFile();
					privateKeyTextField.setText(f.getAbsolutePath());
				}
			}
		});
		privateKeyPathContentPanel.add(privateKeyBtn, BorderLayout.EAST);

		keyPathContentPanel.add(publicKeyPathContentPanel);
		keyPathContentPanel.add(privateKeyPathContentPanel);
		privateKeyPathContentPanel.setVisible(false);
		/* Combobox handling */
		algorithmCombobox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent event) {
				JComboBox comboBox = (JComboBox) event.getSource();
				Object algoritmName = comboBox.getSelectedItem();

				if (algoritmName.equals("RSA")) {
					privateKeyPathContentPanel.setVisible(true);
				} else {
					privateKeyPathContentPanel.setVisible(false);
				}

				AttributeCustomize attributeCustomize = services.get(algoritmName);
				Object[] keySizes = attributeCustomize.getKeySizes();
				keySizeCombobox.removeAllItems();
				for (Object keySize : keySizes) {
					keySizeCombobox.addItem(keySize);
				}
			}
		});
		algorithmCombobox.setSelectedIndex(0);

		actionBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Button actionBtn = (Button) e.getSource();
				Object algorithmName = algorithmCombobox.getSelectedItem();
				Object keySize = keySizeCombobox.getSelectedItem();
				String publicKeyPath = publicKeyTextField.getText();
				String privateKeyPath = privateKeyTextField.getText();
				if (actionBtn.getLabel().equalsIgnoreCase("Generate Key")) {
					boolean isGenerated = false;
					if (String.valueOf(algorithmName).startsWith("PBE")) {
						JOptionPane jop = new JOptionPane();
						String password = jop.showInputDialog(null, "Vui lòng nhập mật khẩu bảo mật");
						if (StringUtils.isNotEmpty(password)) {
							isGenerated = pbeAlgorithm.generateKey(password, String.valueOf(algorithmName),
									publicKeyPath);
						}
					} else {
						if (algorithmName.equals("RSA")) {
							if (keySize.equals("None")) {
								isGenerated = asymmetricSecurity.generativeKeyPair(String.valueOf(algorithmName), -1,
										publicKeyPath, privateKeyPath);
							} else {
								isGenerated = asymmetricSecurity.generativeKeyPair(String.valueOf(algorithmName),
										Integer.valueOf(String.valueOf(keySize)), publicKeyPath, privateKeyPath);
							}
						} else {
							if (keySize.equals("None")) {
								try {
									isGenerated = symmetricSecurity.generateKey(String.valueOf(algorithmName), -1,
											publicKeyPath);
								} catch (IOException e1) {
									// TODO Auto-generated catch block
									JOptionPane.showMessageDialog(null, "Không thành công");
								}
							} else {
								try {
									isGenerated = symmetricSecurity.generateKey(String.valueOf(algorithmName),
											Integer.valueOf(String.valueOf(keySize)), publicKeyPath);
								} catch (NumberFormatException e1) {
									JOptionPane.showMessageDialog(null, "Không thành công");
								} catch (IOException e1) {
									JOptionPane.showMessageDialog(null, "Không thành công");
									;
								}
							}

						}
					}
					if (isGenerated) {
						JOptionPane.showMessageDialog(null, "Tạo khoá thành công");
					}
				}
			}
		});
	}

	private void showSymmetricInterface() {
		/* Symmetric */
		JPanel symmetricPanel = new JPanel();
		tabbedPane.addTab("Symmetric", null, symmetricPanel, null);
		symmetricPanel.setLayout(new BorderLayout(0, 0));

		JPanel symmetricContentPanel = new JPanel();
		symmetricContentPanel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true), "Select",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		symmetricPanel.add(symmetricContentPanel, BorderLayout.CENTER);
		symmetricContentPanel.setLayout(new GridLayout(0, 1, 0, 0));

		JPanel selectContainPanel = new JPanel();
		symmetricContentPanel.add(selectContainPanel);
		selectContainPanel.setLayout(new BorderLayout(0, 0));

		JPanel selectBoxContainerPanel = new JPanel();
		selectContainPanel.add(selectBoxContainerPanel, BorderLayout.NORTH);
		selectBoxContainerPanel.setLayout(new BoxLayout(selectBoxContainerPanel, BoxLayout.X_AXIS));

		encryptBtn = new JRadioButton("Encrypt");
		encryptBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				originalTextTextArea.setText("");
				resultTextTextArea.setText("");
				originalFileTextField.setText("");
				resultFileTextField.setText("");
				JRadioButton jrb = (JRadioButton) e.getSource();
				if (jrb.isSelected()) {
					actionBtn.setLabel("Encrypt");
				}
			}
		});
		selectBtnGroup.add(encryptBtn);
		encryptBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		encryptBtn.setSelected(true);
		encryptBtn.setBorderPainted(true);
		selectBoxContainerPanel.add(encryptBtn);

		decryptBtn = new JRadioButton("Decrypt");
		decryptBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				originalTextTextArea.setText("");
				resultTextTextArea.setText("");
				originalFileTextField.setText("");
				resultFileTextField.setText("");
				JRadioButton jrb = (JRadioButton) e.getSource();
				if (jrb.isSelected()) {
					actionBtn.setLabel("Decrypt");
				}
			}
		});
		selectBtnGroup.add(decryptBtn);
		decryptBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		decryptBtn.setBorderPainted(true);
		selectBoxContainerPanel.add(decryptBtn);

		JPanel algorithmContainerPanel = new JPanel();
		selectContainPanel.add(algorithmContainerPanel, BorderLayout.CENTER);
		algorithmContainerPanel.setLayout(new GridLayout(1, 2, 0, 0));

		JPanel propertyContentPanel = new JPanel();
		propertyContentPanel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 3, true), "Property",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		algorithmContainerPanel.add(propertyContentPanel);
		propertyContentPanel.setLayout(new GridLayout(2, 2, 0, 90));

		JLabel algorithmLabel = new JLabel("Algorithm");
		algorithmLabel.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		algorithmLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
		algorithmLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		algorithmLabel.setHorizontalAlignment(SwingConstants.CENTER);
		propertyContentPanel.add(algorithmLabel);

		Map<String, AttributeCustomize> servicesSym = new HashMap<String, AttributeCustomize>();
		servicesSym.putAll(services);
		servicesSym.remove("RSA");

		JComboBox algorithmsCombobox = new JComboBox(servicesSym.keySet().toArray());
		propertyContentPanel.add(algorithmsCombobox);

		JPanel optionsContentPanel = new JPanel();
		optionsContentPanel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 3, true), "Options",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		algorithmContainerPanel.add(optionsContentPanel);
		optionsContentPanel.setLayout(new GridLayout(2, 2, 0, 90));

		JLabel modeLabel = new JLabel("Mode");
		modeLabel.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		modeLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		modeLabel.setHorizontalAlignment(SwingConstants.CENTER);
		optionsContentPanel.add(modeLabel);

		JComboBox modeCombobox = new JComboBox();
		optionsContentPanel.add(modeCombobox);

		JLabel paddingLabel = new JLabel("Padding");
		paddingLabel.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		paddingLabel.setFont(new Font("Tahoma", Font.BOLD, 16));
		paddingLabel.setHorizontalAlignment(SwingConstants.CENTER);
		optionsContentPanel.add(paddingLabel);

		JComboBox paddingComboBox = new JComboBox();
		optionsContentPanel.add(paddingComboBox);

		JPanel inputContainerPanel = new JPanel();
		inputContainerPanel.setDoubleBuffered(false);
		symmetricContentPanel.add(inputContainerPanel);
		inputContainerPanel.setLayout(new BorderLayout(0, 0));

		JPanel inputContentPanel = new JPanel();
		inputContentPanel.setAutoscrolls(true);
		inputContentPanel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 3, true), "Input & Output",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		inputContainerPanel.add(inputContentPanel);
		inputContentPanel.setLayout(new BorderLayout(0, 0));

		JScrollPane inputBoxPanel = new JScrollPane();
		inputBoxPanel.setBorder(null);
		inputContentPanel.add(inputBoxPanel);

		/* Select Type Container */
		JPanel typeContainerPanel = new JPanel();
		typeContainerPanel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true), "Type",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		typeContainerPanel.setPreferredSize(new Dimension(100, 10));
		inputBoxPanel.setRowHeaderView(typeContainerPanel);
		typeContainerPanel.setLayout(new BoxLayout(typeContainerPanel, BoxLayout.Y_AXIS));

		JRadioButton textRadioButton = new JRadioButton("Text");
		typeBtnGroup.add(textRadioButton);
		textRadioButton.setSelected(true);
		textRadioButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		typeContainerPanel.add(textRadioButton);

		JRadioButton fileRadioButton = new JRadioButton("File");
		typeBtnGroup.add(fileRadioButton);
		fileRadioButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		typeContainerPanel.add(fileRadioButton);

		/* Data Input Container */
		JPanel dataInputContainerPanel = new JPanel();
		dataInputContainerPanel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true), "Data",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		inputBoxPanel.setViewportView(dataInputContainerPanel);
//		inputBoxPanel.setViewportView(dataInputContainerPanel);
		dataInputContainerPanel.setLayout(new BoxLayout(dataInputContainerPanel, BoxLayout.Y_AXIS));

		/* Key Container */
		JPanel keyContainerPanel = new JPanel();
		keyContainerPanel.setAutoscrolls(true);
		dataInputContainerPanel.add(keyContainerPanel);
		keyContainerPanel.setLayout(new BoxLayout(keyContainerPanel, BoxLayout.X_AXIS));

		JLabel keyLabel = new JLabel("Key Path");
		keyLabel.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		keyLabel.setHorizontalAlignment(SwingConstants.CENTER);
		keyLabel.setPreferredSize(new Dimension(100, 16));
		keyLabel.setMaximumSize(new Dimension(46, 16));
		keyLabel.setMinimumSize(new Dimension(46, 16));
		keyContainerPanel.add(keyLabel);

		JTextField keyTextField = new JTextField();
		keyTextField.setEditable(false);
		keyTextField.setBackground(Color.WHITE);
		keyTextField.setFont(new Font("Tahoma", Font.PLAIN, 16));
		keyTextField.setPreferredSize(new Dimension(6, 20));
		keyContainerPanel.add(keyTextField);

		JButton keyBrowseBtn = new JButton("Browse");
		keyBrowseBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int returnVal = fileChooser.showOpenDialog(null);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File f = fileChooser.getSelectedFile();
					keyTextField.setText(f.getAbsolutePath());
				}
			}
		});
		keyBrowseBtn.setBounds(80, 30, 120, 40);
		keyBrowseBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		keyContainerPanel.add(keyBrowseBtn);

		/* Original Container */
		JPanel originalContainerPanel = new JPanel();
		originalContainerPanel.setAutoscrolls(true);
		dataInputContainerPanel.add(originalContainerPanel);
		originalContainerPanel.setLayout(new BoxLayout(originalContainerPanel, BoxLayout.X_AXIS));

		JLabel originalLabel = new JLabel("Original");
		originalLabel.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		originalLabel.setHorizontalAlignment(SwingConstants.CENTER);
		originalLabel.setPreferredSize(new Dimension(100, 16));
		originalContainerPanel.add(originalLabel);

		originalTextTextArea = new JTextArea(2, 1);
		originalTextTextArea.setFont(new Font("Tahoma", Font.PLAIN, 16));
		originalTextTextArea.setBorder(UIManager.getBorder("TextField.border"));
		originalContainerPanel.add(originalTextTextArea);
		originalTextTextArea.setVisible(true);

		originalFileTextField = new JTextField();
		originalFileTextField.setBackground(Color.WHITE);
		originalFileTextField.setEditable(false);
		originalFileTextField.setFont(new Font("Tahoma", Font.PLAIN, 16));
		originalFileTextField.setPreferredSize(new Dimension(6, 20));
		originalContainerPanel.add(originalFileTextField);
		originalFileTextField.setVisible(false);

		JButton originalBrowseBtn = new JButton("Browse");
		originalBrowseBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser jsc = new JFileChooser();
				jsc.setFileSelectionMode(JFileChooser.FILES_ONLY);
				int returnVal = jsc.showOpenDialog(null);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File f = jsc.getSelectedFile();
					originalFileTextField.setText(f.getAbsolutePath());
				}
			}
		});
		originalBrowseBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		originalBrowseBtn.setVisible(false);
		originalContainerPanel.add(originalBrowseBtn);

		/* Result Container */
		JPanel resultContainerPanel = new JPanel();
		dataInputContainerPanel.add(resultContainerPanel);
		resultContainerPanel.setLayout(new BoxLayout(resultContainerPanel, BoxLayout.X_AXIS));

		JLabel resultLabel = new JLabel("Result");
		resultLabel.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		resultLabel.setHorizontalAlignment(SwingConstants.CENTER);
		resultLabel.setPreferredSize(new Dimension(100, 16));
		resultContainerPanel.add(resultLabel);

		resultTextTextArea = new JTextArea(2, 1);
		resultTextTextArea.setFont(new Font("Tahoma", Font.PLAIN, 16));
		resultTextTextArea.setEditable(false);
		resultTextTextArea.setBorder(UIManager.getBorder("TextField.border"));
		resultContainerPanel.add(resultTextTextArea);
		resultTextTextArea.setVisible(true);

		resultFileTextField = new JTextField();
		resultFileTextField.setBackground(Color.WHITE);
		resultFileTextField.setEditable(false);
		resultFileTextField.setFont(new Font("Tahoma", Font.PLAIN, 16));
		resultContainerPanel.add(resultFileTextField);
		resultFileTextField.setVisible(false);

		JButton resultBrowseBtn = new JButton("Open");
		resultBrowseBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					if (StringUtils.isNotEmpty(resultFileTextField.getText()) && fileRadioButton.isSelected()) {
						Desktop.getDesktop().open(new File(resultFileTextField.getText()));
					} else {
						JOptionPane.showMessageDialog(null, "Không thể mở khi đư�?ng dẫn trống");
					}
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		resultBrowseBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		resultBrowseBtn.setVisible(false);
		resultContainerPanel.add(resultBrowseBtn);

		/* Type Action */
		fileRadioButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (fileRadioButton.isSelected()) {
					System.out.println(fileRadioButton.isSelected());
					originalBrowseBtn.setVisible(true);
					originalFileTextField.setVisible(true);
					originalTextTextArea.setVisible(false);
					resultFileTextField.setVisible(true);
					resultTextTextArea.setVisible(false);
					resultBrowseBtn.setVisible(true);

					originalLabel.setText("Source Path");
					resultLabel.setText("Dest Path");
				}
			}
		});
		textRadioButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (textRadioButton.isSelected()) {
					originalBrowseBtn.setVisible(false);
					originalFileTextField.setVisible(false);
					originalTextTextArea.setVisible(true);
					resultFileTextField.setVisible(false);
					resultTextTextArea.setVisible(true);
					resultBrowseBtn.setVisible(false);

					originalLabel.setText("Original");
					resultLabel.setText("Result");
				}
			}
		});

		/* Combobox handling */
		algorithmsCombobox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent event) {
				System.out.println("-----------------");
				JComboBox comboBox = (JComboBox) event.getSource();
				Object selected = comboBox.getSelectedItem();
				AttributeCustomize attribute = services.get(selected);
				Object[] modes = attribute.getMode();
				Object[] paddings = attribute.getPadding();
				if (modes != null) {
					modeCombobox.removeAllItems();
					for (Object mode : modes) {
						modeCombobox.addItem(mode);
					}
				}
				if (paddings != null) {
					paddingComboBox.removeAllItems();
					for (Object padding : paddings) {
						System.out.println(padding);
						paddingComboBox.addItem(padding);
					}
				}
			}
		});
		algorithmsCombobox.setSelectedIndex(0);

		JSeparator separator = new JSeparator();
		propertyContentPanel.add(separator);

		JSeparator separator_1 = new JSeparator();
		propertyContentPanel.add(separator_1);

		actionBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent event) {
				if (tabbedPane.getSelectedIndex() == 1) {
					String type = null;
					String original = null;
					String keyPath = keyTextField.getText();
					if (textRadioButton.isSelected()) {
						type = "text";
						original = originalTextTextArea.getText();
					} else if (fileRadioButton.isSelected()) {
						type = "file";
						original = originalFileTextField.getText();
					}
					String algorithmName = String.valueOf(algorithmsCombobox.getSelectedItem());
					String mode = String.valueOf(modeCombobox.getSelectedItem());
					String padding = String.valueOf(paddingComboBox.getSelectedItem());
					SymmetricAlgorithm sAlgo = new SymmetricAlgorithm(algorithmName, mode, padding);
					if (encryptBtn.isSelected() && actionBtn.getLabel().equals("Encrypt")) {
						String cipherStringOrCipherPath = null;
						/* __SET UP VALUE */
						if (algorithmName.startsWith("PBE")) {
							cipherStringOrCipherPath = pbeAlgorithm.encryption(algorithmName, keyPath, original,
									pbeAlgorithm.getSaltValue(), pbeAlgorithm.getIterationCount());
						} else {
							try {
								cipherStringOrCipherPath = symmetricSecurity.encrypt(original, keyPath, sAlgo, type);
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
						/* __SET VALUE for INPUT */
						if (type.equals("text"))
							resultTextTextArea.setText(cipherStringOrCipherPath);
						else if (type.equals("file")) {
							resultFileTextField.setText(cipherStringOrCipherPath);
						}
					} else if (decryptBtn.isSelected() && actionBtn.getLabel().equals("Decrypt")) {
						String plainStringOrPlainPath = null;
						/* __SET UP VALUE */
						if (algorithmName.startsWith("PBE")) {
							plainStringOrPlainPath = pbeAlgorithm.decryption(algorithmName, keyPath, original,
									pbeAlgorithm.getSaltValue(), pbeAlgorithm.getIterationCount());
						} else {
							try {
								plainStringOrPlainPath = symmetricSecurity.decrypt(original, keyPath, sAlgo, type);
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
						/* __SET VALUE for INPUT */
						if (type.equals("text"))
							resultTextTextArea.setText(plainStringOrPlainPath);
						else if (type.equals("file")) {
							resultFileTextField.setText(plainStringOrPlainPath);
						}
					}
				}
			}
		});

	}

	private void showAsymmetricInterface() {
		JPanel asymmetricPanel = new JPanel();
		tabbedPane.addTab("Asymmetric", null, asymmetricPanel, null);
		asymmetricPanel.setLayout(new BorderLayout(0, 0));

		JPanel asymmetricContentPanel = new JPanel();
		asymmetricContentPanel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true), "Select",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		asymmetricPanel.add(asymmetricContentPanel, BorderLayout.CENTER);
		asymmetricContentPanel.setLayout(new GridLayout(0, 1, 0, 0));

		JPanel selectContainPanelAsym = new JPanel();
		asymmetricContentPanel.add(selectContainPanelAsym);
		selectContainPanelAsym.setLayout(new BorderLayout(0, 0));

		JPanel selectBoxContainerPanelAsym = new JPanel();
		selectContainPanelAsym.add(selectBoxContainerPanelAsym, BorderLayout.NORTH);
		selectBoxContainerPanelAsym.setLayout(new BoxLayout(selectBoxContainerPanelAsym, BoxLayout.X_AXIS));

		encryptBtnAsym = new JRadioButton("Encrypt");
		selectBtnGroupAsym.add(encryptBtnAsym);
		encryptBtnAsym.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		encryptBtnAsym.setSelected(true);
		encryptBtnAsym.setBorderPainted(true);
		selectBoxContainerPanelAsym.add(encryptBtnAsym);

		decryptBtnAsym = new JRadioButton("Decrypt");

		selectBtnGroupAsym.add(decryptBtnAsym);
		decryptBtnAsym.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		decryptBtnAsym.setBorderPainted(true);
		selectBoxContainerPanelAsym.add(decryptBtnAsym);

		JPanel algorithmContainerPanelAsym = new JPanel();
		selectContainPanelAsym.add(algorithmContainerPanelAsym, BorderLayout.CENTER);
		algorithmContainerPanelAsym.setLayout(new GridLayout(1, 2, 0, 0));

		JPanel propertyContentPanelAsym = new JPanel();
		propertyContentPanelAsym.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 3, true), "Property",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		algorithmContainerPanelAsym.add(propertyContentPanelAsym);
		propertyContentPanelAsym.setLayout(new GridLayout(2, 2, 0, 90));

		JLabel algorithmLabelAsym = new JLabel("Algorithm");
		algorithmLabelAsym.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		algorithmLabelAsym.setAlignmentX(Component.CENTER_ALIGNMENT);
		algorithmLabelAsym.setFont(new Font("Tahoma", Font.BOLD, 16));
		algorithmLabelAsym.setHorizontalAlignment(SwingConstants.CENTER);
		propertyContentPanelAsym.add(algorithmLabelAsym);

		Map<String, AttributeCustomize> servicesAsym = new HashMap<String, AttributeCustomize>();
		servicesAsym.put("RSA", services.get("RSA"));

		JComboBox algorithmsComboboxAsym = new JComboBox(servicesAsym.keySet().toArray());
		propertyContentPanelAsym.add(algorithmsComboboxAsym);

		JLabel keySizeLabelAsym = new JLabel("");
		keySizeLabelAsym.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		keySizeLabelAsym.setFont(new Font("Tahoma", Font.BOLD, 16));
		keySizeLabelAsym.setHorizontalAlignment(SwingConstants.CENTER);
		propertyContentPanelAsym.add(keySizeLabelAsym);

		JPanel optionsContentPanelAsym = new JPanel();
		optionsContentPanelAsym.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 3, true), "Options",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		algorithmContainerPanelAsym.add(optionsContentPanelAsym);
		optionsContentPanelAsym.setLayout(new GridLayout(2, 2, 0, 90));

		JLabel modeLabelAsym = new JLabel("Mode");
		modeLabelAsym.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		modeLabelAsym.setFont(new Font("Tahoma", Font.BOLD, 16));
		modeLabelAsym.setHorizontalAlignment(SwingConstants.CENTER);
		optionsContentPanelAsym.add(modeLabelAsym);

		JComboBox modeComboboxAsym = new JComboBox();
		optionsContentPanelAsym.add(modeComboboxAsym);

		JLabel paddingLabelAsym = new JLabel("Padding");
		paddingLabelAsym.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		paddingLabelAsym.setFont(new Font("Tahoma", Font.BOLD, 16));
		paddingLabelAsym.setHorizontalAlignment(SwingConstants.CENTER);
		optionsContentPanelAsym.add(paddingLabelAsym);

		JComboBox paddingComboBoxAsym = new JComboBox();
		optionsContentPanelAsym.add(paddingComboBoxAsym);

		JPanel inputContainerPanelAsym = new JPanel();
		inputContainerPanelAsym.setDoubleBuffered(false);
		asymmetricContentPanel.add(inputContainerPanelAsym);
		inputContainerPanelAsym.setLayout(new BorderLayout(0, 0));

		JPanel inputContentPanelAsym = new JPanel();
		inputContentPanelAsym.setAutoscrolls(true);
		inputContentPanelAsym.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 3, true), "Input & Output",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		inputContainerPanelAsym.add(inputContentPanelAsym);
		inputContentPanelAsym.setLayout(new BorderLayout(0, 0));

		JScrollPane inputBoxPanelAsym = new JScrollPane();
		inputBoxPanelAsym.setBorder(null);
		inputContentPanelAsym.add(inputBoxPanelAsym);

		/* Select Type Container */
		JPanel typeContainerPanelAsym = new JPanel();
		typeContainerPanelAsym.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true), "Type",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		typeContainerPanelAsym.setPreferredSize(new Dimension(100, 10));
		inputBoxPanelAsym.setRowHeaderView(typeContainerPanelAsym);
		typeContainerPanelAsym.setLayout(new BoxLayout(typeContainerPanelAsym, BoxLayout.Y_AXIS));

		JRadioButton textRadioButtonAsym = new JRadioButton("Text");
		typeBtnGroupAsym.add(textRadioButtonAsym);
		textRadioButtonAsym.setSelected(true);
		textRadioButtonAsym.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		typeContainerPanelAsym.add(textRadioButtonAsym);

		/* Data Input Container */
		JPanel dataInputContainerPanelAsym = new JPanel();
		dataInputContainerPanelAsym.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true), "Data",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		inputBoxPanelAsym.setViewportView(dataInputContainerPanelAsym);
//		inputBoxPanel.setViewportView(dataInputContainerPanel);
		dataInputContainerPanelAsym.setLayout(new BoxLayout(dataInputContainerPanelAsym, BoxLayout.Y_AXIS));

		/* Key Container */
		JPanel keyContainerPanelAsym = new JPanel();
		keyContainerPanelAsym.setAutoscrolls(true);
		dataInputContainerPanelAsym.add(keyContainerPanelAsym);
		keyContainerPanelAsym.setLayout(new BoxLayout(keyContainerPanelAsym, BoxLayout.X_AXIS));

		JLabel keyLabelAsym = new JLabel("Public Key Path");
		keyLabelAsym.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		keyLabelAsym.setHorizontalAlignment(SwingConstants.CENTER);
		keyLabelAsym.setPreferredSize(new Dimension(100, 16));
		keyLabelAsym.setMaximumSize(new Dimension(46, 16));
		keyLabelAsym.setMinimumSize(new Dimension(46, 16));
		keyContainerPanelAsym.add(keyLabelAsym);

		JTextField keyTextFieldAsym = new JTextField();
		keyTextFieldAsym.setFont(new Font("Tahoma", Font.PLAIN, 16));
		keyTextFieldAsym.setBackground(Color.WHITE);
		keyTextFieldAsym.setEditable(false);
		keyTextFieldAsym.setPreferredSize(new Dimension(6, 20));
		keyContainerPanelAsym.add(keyTextFieldAsym);

		JButton keyBrowseBtnAsym = new JButton("Browse");
		keyBrowseBtnAsym.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser jsc = new JFileChooser();
				jsc.setFileSelectionMode(JFileChooser.FILES_ONLY);
				int returnVal = jsc.showOpenDialog(null);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File f = jsc.getSelectedFile();
					keyTextFieldAsym.setText(f.getAbsolutePath());
				}
			}
		});
		keyBrowseBtnAsym.setBounds(80, 30, 120, 40);
		keyBrowseBtnAsym.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		keyContainerPanelAsym.add(keyBrowseBtnAsym);

		/* Original Container */
		JPanel originalContainerPanelAsym = new JPanel();
		originalContainerPanelAsym.setAutoscrolls(true);
		dataInputContainerPanelAsym.add(originalContainerPanelAsym);
		originalContainerPanelAsym.setLayout(new BoxLayout(originalContainerPanelAsym, BoxLayout.X_AXIS));

		JLabel originalLabelAsym = new JLabel("Original");
		originalLabelAsym.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		originalLabelAsym.setHorizontalAlignment(SwingConstants.CENTER);
		originalLabelAsym.setPreferredSize(new Dimension(100, 16));
		originalContainerPanelAsym.add(originalLabelAsym);

		JTextArea originalTextTextAreaAsym = new JTextArea(3, 1);
		originalTextTextAreaAsym.setFont(new Font("Tahoma", Font.PLAIN, 16));
		originalTextTextAreaAsym.setBorder(UIManager.getBorder("TextField.border"));
		originalContainerPanelAsym.add(originalTextTextAreaAsym);
		originalTextTextAreaAsym.setVisible(true);

		/* Result Container */
		JPanel resultContainerPanelAsym = new JPanel();
		dataInputContainerPanelAsym.add(resultContainerPanelAsym);
		resultContainerPanelAsym.setLayout(new BoxLayout(resultContainerPanelAsym, BoxLayout.X_AXIS));

		JLabel resultLabelAsym = new JLabel("Result");
		resultLabelAsym.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		resultLabelAsym.setHorizontalAlignment(SwingConstants.CENTER);
		resultLabelAsym.setPreferredSize(new Dimension(100, 16));
		resultContainerPanelAsym.add(resultLabelAsym);

		JTextArea resultTextTextAreaAsym = new JTextArea(3, 1);
		resultTextTextAreaAsym.setFont(new Font("Tahoma", Font.PLAIN, 16));
		resultTextTextAreaAsym.setEditable(false);
		resultTextTextAreaAsym.setBorder(UIManager.getBorder("TextField.border"));
		resultContainerPanelAsym.add(resultTextTextAreaAsym);
		resultTextTextAreaAsym.setVisible(true);

		/* Type Action */
		encryptBtnAsym.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JRadioButton jrb = (JRadioButton) e.getSource();
				originalTextTextAreaAsym.setText("");
				resultTextTextAreaAsym.setText("");
				if (jrb.isSelected()) {
					actionBtn.setLabel("Encrypt");
					keyLabelAsym.setText("Public Key Path");
				}
			}
		});

		decryptBtnAsym.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JRadioButton jrb = (JRadioButton) e.getSource();
				originalTextTextAreaAsym.setText("");
				resultTextTextAreaAsym.setText("");
				if (jrb.isSelected()) {
					actionBtn.setLabel("Decrypt");
					keyLabelAsym.setText("Private Key Path");
				}
			}
		});

		textRadioButtonAsym.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (textRadioButtonAsym.isSelected()) {
					originalTextTextAreaAsym.setVisible(true);
					resultTextTextAreaAsym.setVisible(true);
				}
			}
		});

		algorithmsComboboxAsym.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JComboBox jcb = (JComboBox) e.getSource();
				Object algorithmName = jcb.getSelectedItem();
				AttributeCustomize attribute = servicesAsym.get(algorithmName);
				Object[] modes = attribute.getMode();
				Object[] paddings = attribute.getPadding();
				if (modes != null) {
					modeComboboxAsym.removeAllItems();
					for (Object mode : modes) {
						modeComboboxAsym.addItem(mode);
					}
				}
				if (paddings != null) {
					paddingComboBoxAsym.removeAllItems();
					for (Object padding : paddings) {
						paddingComboBoxAsym.addItem(padding);
					}
				}
			}
		});

		algorithmsComboboxAsym.setSelectedIndex(0);

		actionBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent event) {
				if (tabbedPane.getSelectedIndex() == 2) {
					String type = null;
					String original = null;
					String keyPath = keyTextFieldAsym.getText();
					if (textRadioButtonAsym.isSelected()) {
						type = Constant.TEXT_TYPE;
						original = originalTextTextAreaAsym.getText();
					}
					String algorithmName = String.valueOf(algorithmsComboboxAsym.getSelectedItem());
					String mode = String.valueOf(modeComboboxAsym.getSelectedItem());
					String padding = String.valueOf(paddingComboBoxAsym.getSelectedItem());
					String value = null;
					AsymmetricAlgorithm asAlgo = new AsymmetricAlgorithm(algorithmName, mode, padding);
					if (encryptBtnAsym.isSelected() && actionBtn.getLabel().equals("Encrypt")) {
						/* __SET UP VALUE to setText in textField */
						try {
							value = asymmetricSecurity.encryption(original, keyPath, asAlgo, type);
						} catch (IOException e) {
							// TODO Auto-generated catch block
							JOptionPane.showMessageDialog(null, "Không thành công");
						}
					} else if (decryptBtnAsym.isSelected() && actionBtn.getLabel().equals("Decrypt")) {
						try {
							System.out.println("OKKKKKKKKKks");
							value = asymmetricSecurity.decryption(original, keyPath, asAlgo, type);
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					System.out.println(value);
					/* __SET VALUE for INPUT */
					if (type.equals(Constant.TEXT_TYPE)) {
						resultTextTextAreaAsym.setText(value);
					}
				}
			}
		});
	}

	private void showHashInterface() {
		JPanel hashPanel = new JPanel();
		tabbedPane.addTab("Hash", null, hashPanel, null);
		hashPanel.setLayout(new BorderLayout(0, 0));

		JPanel hashContentPanel = new JPanel();
		hashContentPanel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true), "Select",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		hashPanel.add(hashContentPanel, BorderLayout.CENTER);
		hashContentPanel.setLayout(new GridLayout(0, 1, 0, 0));

		JPanel selectContainPanelHash = new JPanel();
		hashContentPanel.add(selectContainPanelHash);
		selectContainPanelHash.setLayout(new BorderLayout(0, 0));

		JPanel algorithmContainerPanelHash = new JPanel();
		selectContainPanelHash.add(algorithmContainerPanelHash, BorderLayout.CENTER);
		algorithmContainerPanelHash.setLayout(new BoxLayout(algorithmContainerPanelHash, BoxLayout.X_AXIS));

		JPanel propertyContentPanelHash = new JPanel();
		propertyContentPanelHash.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 3, true), "Property",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		algorithmContainerPanelHash.add(propertyContentPanelHash);
		propertyContentPanelHash.setLayout(new GridLayout(2, 2, 0, 90));

		JLabel algorithmLabelHash = new JLabel("Algorithm");
		algorithmLabelHash.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		algorithmLabelHash.setAlignmentX(Component.CENTER_ALIGNMENT);
		algorithmLabelHash.setFont(new Font("Tahoma", Font.BOLD, 16));
		algorithmLabelHash.setHorizontalAlignment(SwingConstants.CENTER);
		propertyContentPanelHash.add(algorithmLabelHash);

		Object[] hashAlgorithmNames = this.hashAlgorithm.getHashAlgorithms();
		JComboBox algorithmsComboboxHash = new JComboBox(hashAlgorithmNames);
		algorithmsComboboxHash.setFont(new Font("Tahoma", Font.BOLD, 13));
		propertyContentPanelHash.add(algorithmsComboboxHash);

		JLabel keySizeLabelHash = new JLabel("");
		keySizeLabelHash.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		keySizeLabelHash.setFont(new Font("Tahoma", Font.BOLD, 16));
		keySizeLabelHash.setHorizontalAlignment(SwingConstants.CENTER);
		propertyContentPanelHash.add(keySizeLabelHash);
//		
		JPanel inputContainerPanelHash = new JPanel();
		inputContainerPanelHash.setDoubleBuffered(false);
		hashContentPanel.add(inputContainerPanelHash);
		inputContainerPanelHash.setLayout(new BorderLayout(0, 0));

		JPanel inputContentPanelHash = new JPanel();
		inputContentPanelHash.setAutoscrolls(true);
		inputContentPanelHash.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 3, true), "Input",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		inputContainerPanelHash.add(inputContentPanelHash);
		inputContentPanelHash.setLayout(new BorderLayout(0, 0));

		JScrollPane inputBoxPanelHash = new JScrollPane();
		inputBoxPanelHash.setBorder(null);
		inputContentPanelHash.add(inputBoxPanelHash);

		/* Select Type Container */
		JPanel typeContainerPanelHash = new JPanel();
		typeContainerPanelHash.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true), "Type",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		typeContainerPanelHash.setPreferredSize(new Dimension(100, 10));
		inputBoxPanelHash.setRowHeaderView(typeContainerPanelHash);
		typeContainerPanelHash.setLayout(new BoxLayout(typeContainerPanelHash, BoxLayout.Y_AXIS));

		JRadioButton textRadioButtonHash = new JRadioButton("Text");
		typeBtnGroupHash.add(textRadioButtonHash);
//		typeBtnGroupAsym.add(textRadioButtonHash);
		textRadioButtonHash.setSelected(true);
		textRadioButtonHash.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		typeContainerPanelHash.add(textRadioButtonHash);

		JRadioButton fileRadioButtonHash = new JRadioButton("File");
		typeBtnGroupHash.add(fileRadioButtonHash);
//		typeBtnGroupAsym.add(fileRadioButtonAsym);
		fileRadioButtonHash.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		typeContainerPanelHash.add(fileRadioButtonHash);

		/* Data Input Container */
		JPanel dataInputContainerPanelHash = new JPanel();
		dataInputContainerPanelHash.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true),
				"Data Input", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		inputBoxPanelHash.setViewportView(dataInputContainerPanelHash);
//		inputBoxPanel.setViewportView(dataInputContainerPanel);
		dataInputContainerPanelHash.setLayout(new BoxLayout(dataInputContainerPanelHash, BoxLayout.Y_AXIS));

		/* Original Container */
		JPanel originalContainerPanelHash = new JPanel();
		originalContainerPanelHash.setAutoscrolls(true);
		dataInputContainerPanelHash.add(originalContainerPanelHash);
		originalContainerPanelHash.setLayout(new BoxLayout(originalContainerPanelHash, BoxLayout.X_AXIS));

		JLabel originalLabelHash = new JLabel("Original");
		originalLabelHash.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		originalLabelHash.setHorizontalAlignment(SwingConstants.CENTER);
		originalLabelHash.setPreferredSize(new Dimension(100, 16));
		originalContainerPanelHash.add(originalLabelHash);

		JTextArea originalTextTextAreaHash = new JTextArea(3, 1);
		originalTextTextAreaHash.setFont(new Font("Tahoma", Font.PLAIN, 16));
		originalTextTextAreaHash.setBorder(UIManager.getBorder("TextField.border"));
		originalContainerPanelHash.add(originalTextTextAreaHash);
		originalTextTextAreaHash.setVisible(true);

		JTextField originalFileTextFieldHash = new JTextField();
		originalFileTextFieldHash.setBackground(Color.WHITE);
		originalFileTextFieldHash.setFont(new Font("Tahoma", Font.PLAIN, 16));
		originalFileTextFieldHash.setEditable(false);
		originalFileTextFieldHash.setPreferredSize(new Dimension(6, 20));
		originalContainerPanelHash.add(originalFileTextFieldHash);
		originalFileTextFieldHash.setVisible(false);

		JButton originalBrowseBtnHash = new JButton("Browse");
		originalBrowseBtnHash.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		originalBrowseBtnHash.setVisible(false);
		originalContainerPanelHash.add(originalBrowseBtnHash);

		/* Result Container */
		JPanel resultContainerPanelHash = new JPanel();
		dataInputContainerPanelHash.add(resultContainerPanelHash);
		resultContainerPanelHash.setLayout(new BoxLayout(resultContainerPanelHash, BoxLayout.X_AXIS));

		JLabel resultLabelHash = new JLabel("Result");
		resultLabelHash.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		resultLabelHash.setHorizontalAlignment(SwingConstants.CENTER);
		resultLabelHash.setPreferredSize(new Dimension(100, 16));
		resultContainerPanelHash.add(resultLabelHash);

		JTextArea resultTextTextAreaHash = new JTextArea(3, 1);
		resultTextTextAreaHash.setFont(new Font("Tahoma", Font.PLAIN, 16));
		resultTextTextAreaHash.setEditable(false);
		resultTextTextAreaHash.setBorder(UIManager.getBorder("TextField.border"));
		resultContainerPanelHash.add(resultTextTextAreaHash);
		resultTextTextAreaHash.setVisible(true);

		JTextField resultFileTextFieldHash = new JTextField();
		resultFileTextFieldHash.setBackground(Color.WHITE);
		resultFileTextFieldHash.setEditable(false);
		resultFileTextFieldHash.setFont(new Font("Tahoma", Font.PLAIN, 16));
		resultContainerPanelHash.add(resultFileTextFieldHash);
		resultFileTextFieldHash.setVisible(false);

		JButton resultBrowseBtnHash = new JButton("Browse");
		resultBrowseBtnHash.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		resultBrowseBtnHash.setVisible(false);
		resultContainerPanelHash.add(resultBrowseBtnHash);

		textRadioButtonHash.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (textRadioButtonHash.isSelected()) {
					originalBrowseBtnHash.setVisible(false);
					originalFileTextFieldHash.setVisible(false);
					originalTextTextAreaHash.setVisible(true);
					resultFileTextFieldHash.setVisible(false);
					resultTextTextAreaHash.setVisible(true);
					resultBrowseBtnHash.setVisible(false);
					originalLabelHash.setText("Original");
				}
			}
		});

		/* Type Action */
		fileRadioButtonHash.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (fileRadioButtonHash.isSelected()) {
					originalBrowseBtnHash.setVisible(true);
					originalFileTextFieldHash.setVisible(true);
					originalTextTextAreaHash.setVisible(false);
					resultFileTextFieldHash.setVisible(true);
					resultTextTextAreaHash.setVisible(false);
					resultBrowseBtnHash.setVisible(true);
					originalLabelHash.setText("Source Path");
					resultLabelHash.setText("Dest Path");
				}
			}
		});

		originalBrowseBtnHash.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int returnVal = fileChooser.showOpenDialog(null);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File f = fileChooser.getSelectedFile();
					originalFileTextFieldHash.setText(f.getAbsolutePath());
				}
			}
		});
		resultBrowseBtnHash.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					if (StringUtils.isNotEmpty(resultFileTextFieldHash.getText()) && fileRadioButtonHash.isSelected()) {
						Desktop.getDesktop().open(new File(resultFileTextFieldHash.getText()));
					} else {
						JOptionPane.showMessageDialog(null, "Không thể mở khi đư�?ng dẫn trống");
					}
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		actionBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent event) {
				if (tabbedPane.getSelectedIndex() == 4 && actionBtn.getLabel().equals("Run")) {
					String type = null;
					String original = null;
					if (textRadioButtonHash.isSelected()) {
						type = "text";
						original = textRadioButtonHash.getText();
					} else if (fileRadioButtonHash.isSelected()) {
						type = "file";
						original = originalFileTextFieldHash.getText();
					}
					String algorithmName = String.valueOf(algorithmsComboboxHash.getSelectedItem());
					String value = null;
					/* __SET UP VALUE to setText in textField */
					value = hashAlgorithm.checksum(original, algorithmName, type);
					/* __SET VALUE for INPUT */
					if (type.equals("text"))
						resultTextTextAreaHash.setText(value);
					else if (type.equals("file")) {
						resultFileTextFieldHash.setText(value);
					}
				}
			}
		});
	}

	public void showCombineInterface() {
		JPanel combinePanel = new JPanel();
		tabbedPane.addTab("Combine", null, combinePanel, null);
		combinePanel.setLayout(new BorderLayout(0, 0));

		JPanel combineContentPanel = new JPanel();
		combineContentPanel.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true), "Select",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		combinePanel.add(combineContentPanel, BorderLayout.CENTER);
		combineContentPanel.setLayout(new GridLayout(0, 1, 0, 0));

		JPanel selectContainPanelCombine = new JPanel();
		combineContentPanel.add(selectContainPanelCombine);
		selectContainPanelCombine.setLayout(new BorderLayout(0, 0));

		JPanel selectBoxContainerPanelCombine = new JPanel();
		selectContainPanelCombine.add(selectBoxContainerPanelCombine, BorderLayout.NORTH);
		selectBoxContainerPanelCombine.setLayout(new BoxLayout(selectBoxContainerPanelCombine, BoxLayout.X_AXIS));

		encryptBtnCombine = new JRadioButton("Encrypt");
		selectBtnGroupCombine.add(encryptBtnCombine);
		encryptBtnCombine.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		encryptBtnCombine.setSelected(true);
		encryptBtnCombine.setBorderPainted(true);
		selectBoxContainerPanelCombine.add(encryptBtnCombine);

		decryptBtnCombine = new JRadioButton("Decrypt");
		selectBtnGroupCombine.add(decryptBtnCombine);
		decryptBtnCombine.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		decryptBtnCombine.setBorderPainted(true);
		selectBoxContainerPanelCombine.add(decryptBtnCombine);

		JPanel algorithmContainerPanelCombine = new JPanel();
		selectContainPanelCombine.add(algorithmContainerPanelCombine, BorderLayout.CENTER);
		algorithmContainerPanelCombine.setLayout(new GridLayout(0, 2, 0, 0));

		JPanel symContentPanelCombine = new JPanel();
		symContentPanelCombine.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 3, true),
				"Symmetric Algorithm", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		algorithmContainerPanelCombine.add(symContentPanelCombine);
		symContentPanelCombine.setLayout(new GridLayout(3, 2, 40, 0));

		JLabel sAlgorithmLabelCombine = new JLabel("Algorithm");
		sAlgorithmLabelCombine.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		sAlgorithmLabelCombine.setAlignmentX(Component.CENTER_ALIGNMENT);
		sAlgorithmLabelCombine.setFont(new Font("Tahoma", Font.BOLD, 16));
		sAlgorithmLabelCombine.setHorizontalAlignment(SwingConstants.CENTER);
		symContentPanelCombine.add(sAlgorithmLabelCombine);

		Map<String, AttributeCustomize> sServicesCombine = new HashMap<String, AttributeCustomize>();
		services.forEach(((k, v) -> {
			if (!k.startsWith("PBE")) {
				sServicesCombine.put(k, v);
			}
		}));
		sServicesCombine.remove("RSA");
		JComboBox sAlgorithmComboboxCombine = new JComboBox(sServicesCombine.keySet().toArray());
		sAlgorithmComboboxCombine.setFont(new Font("Tahoma", Font.BOLD, 13));
		symContentPanelCombine.add(sAlgorithmComboboxCombine);

		JPanel asymContentPanelCombine = new JPanel();
		asymContentPanelCombine.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 3, true),
				"Asymmetric Algorithm", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		algorithmContainerPanelCombine.add(asymContentPanelCombine);
		asymContentPanelCombine.setLayout(new GridLayout(3, 2, 0, 0));

		JLabel asAlgorithmLabelCombine = new JLabel("Algorithm");
		asAlgorithmLabelCombine.setHorizontalAlignment(SwingConstants.CENTER);
		asAlgorithmLabelCombine.setFont(new Font("Tahoma", Font.BOLD, 16));
		asAlgorithmLabelCombine.setAlignmentX(0.5f);
		asymContentPanelCombine.add(asAlgorithmLabelCombine);

		Map<String, AttributeCustomize> asServicesCombine = new HashMap<String, AttributeCustomize>();
		asServicesCombine.put("RSA", services.get("RSA"));
		JComboBox asAlgorithmComboboxCombine = new JComboBox(asServicesCombine.keySet().toArray());
		asAlgorithmComboboxCombine.setFont(new Font("Tahoma", Font.BOLD, 13));
		asymContentPanelCombine.add(asAlgorithmComboboxCombine);

		JLabel asModeLabelCombine = new JLabel("Mode");
		asModeLabelCombine.setHorizontalAlignment(SwingConstants.CENTER);
		asModeLabelCombine.setFont(new Font("Tahoma", Font.BOLD, 16));
		asModeLabelCombine.setAlignmentX(0.5f);
		asymContentPanelCombine.add(asModeLabelCombine);

		JComboBox asModeComboboxCombine = new JComboBox(new Object[] {});
		asModeComboboxCombine.setFont(new Font("Tahoma", Font.BOLD, 13));
		asymContentPanelCombine.add(asModeComboboxCombine);

		JLabel asPaddingLabelCombine = new JLabel("Padding");
		asPaddingLabelCombine.setHorizontalAlignment(SwingConstants.CENTER);
		asPaddingLabelCombine.setFont(new Font("Tahoma", Font.BOLD, 16));
		asymContentPanelCombine.add(asPaddingLabelCombine);

		JComboBox asPaddingComboboxCombine = new JComboBox(new Object[] {});
		asPaddingComboboxCombine.setFont(new Font("Tahoma", Font.BOLD, 13));
		asymContentPanelCombine.add(asPaddingComboboxCombine);

		JPanel inputContainerPanelCombine = new JPanel();
		inputContainerPanelCombine.setDoubleBuffered(false);
		combineContentPanel.add(inputContainerPanelCombine);
		inputContainerPanelCombine.setLayout(new BorderLayout(0, 0));

		JPanel inputContentPanelCombine = new JPanel();
		inputContentPanelCombine.setAutoscrolls(true);
		inputContentPanelCombine.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 3, true),
				"Input & Output", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		inputContainerPanelCombine.add(inputContentPanelCombine);
		inputContentPanelCombine.setLayout(new BorderLayout(0, 0));

		JScrollPane inputBoxPanelCombine = new JScrollPane();
		inputBoxPanelCombine.setBorder(null);
		inputContentPanelCombine.add(inputBoxPanelCombine);

		/* Select Type Container */
		JPanel typeContainerPanelCombine = new JPanel();
		typeContainerPanelCombine.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true), "Type",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		typeContainerPanelCombine.setPreferredSize(new Dimension(100, 10));
		inputBoxPanelCombine.setRowHeaderView(typeContainerPanelCombine);
		typeContainerPanelCombine.setLayout(new BoxLayout(typeContainerPanelCombine, BoxLayout.Y_AXIS));

		JRadioButton fileRadioButtonCombine = new JRadioButton("File");
		fileRadioButtonCombine.setSelected(true);
		fileRadioButtonCombine.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		typeContainerPanelCombine.add(fileRadioButtonCombine);

		/* Data Input Container */
		JPanel dataInputContainerPanelCombine = new JPanel();
		dataInputContainerPanelCombine.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0), 2, true), "Data",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		inputBoxPanelCombine.setViewportView(dataInputContainerPanelCombine);
//		inputBoxPanel.setViewportView(dataInputContainerPanel);
		dataInputContainerPanelCombine.setLayout(new BoxLayout(dataInputContainerPanelCombine, BoxLayout.Y_AXIS));

		/* Key Container */
		JPanel keyContainerPanelCombine = new JPanel();
		keyContainerPanelCombine.setAutoscrolls(true);
		dataInputContainerPanelCombine.add(keyContainerPanelCombine);
		keyContainerPanelCombine.setLayout(new BoxLayout(keyContainerPanelCombine, BoxLayout.X_AXIS));

		JLabel keyLabelCombine = new JLabel("Public Key Path");
		keyLabelCombine.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		keyLabelCombine.setHorizontalAlignment(SwingConstants.CENTER);
		keyLabelCombine.setPreferredSize(new Dimension(100, 16));
		keyLabelCombine.setMaximumSize(new Dimension(46, 16));
		keyLabelCombine.setMinimumSize(new Dimension(46, 16));
		keyContainerPanelCombine.add(keyLabelCombine);

		JTextField keyTextFieldCombine = new JTextField();
		keyTextFieldCombine.setFont(new Font("Tahoma", Font.PLAIN, 16));
		keyTextFieldCombine.setBackground(Color.WHITE);
		keyTextFieldCombine.setEditable(false);
		keyTextFieldCombine.setPreferredSize(new Dimension(6, 20));
		keyContainerPanelCombine.add(keyTextFieldCombine);

		JButton keyBrowseBtnCombine = new JButton("Browse");
		keyBrowseBtnCombine.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int returnVal = fileChooser.showOpenDialog(null);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File f = fileChooser.getSelectedFile();
					keyTextFieldCombine.setText(f.getAbsolutePath());
				}
			}
		});
		keyBrowseBtnCombine.setBounds(80, 30, 120, 40);
		keyBrowseBtnCombine.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		keyContainerPanelCombine.add(keyBrowseBtnCombine);

		/* Original Container */
		JPanel originalContainerPanelCombine = new JPanel();
		originalContainerPanelCombine.setAutoscrolls(true);
		dataInputContainerPanelCombine.add(originalContainerPanelCombine);
		originalContainerPanelCombine.setLayout(new BoxLayout(originalContainerPanelCombine, BoxLayout.X_AXIS));

		JLabel originalLabelCombine = new JLabel("Original");
		originalLabelCombine.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		originalLabelCombine.setHorizontalAlignment(SwingConstants.CENTER);
		originalLabelCombine.setPreferredSize(new Dimension(100, 16));
		originalContainerPanelCombine.add(originalLabelCombine);

		JTextField originalFileTextFieldCombine = new JTextField();
		originalFileTextFieldCombine.setFont(new Font("Tahoma", Font.PLAIN, 16));
		originalFileTextFieldCombine.setBackground(Color.WHITE);
		originalFileTextFieldCombine.setEditable(false);
		originalFileTextFieldCombine.setPreferredSize(new Dimension(6, 20));
		originalContainerPanelCombine.add(originalFileTextFieldCombine);

		JButton originalBrowseBtnCombine = new JButton("Browse");
		originalBrowseBtnCombine.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		originalContainerPanelCombine.add(originalBrowseBtnCombine);

		/* Result Container */
		JPanel resultContainerPanelCombine = new JPanel();
		dataInputContainerPanelCombine.add(resultContainerPanelCombine);
		resultContainerPanelCombine.setLayout(new BoxLayout(resultContainerPanelCombine, BoxLayout.X_AXIS));

		JLabel resultLabelCombine = new JLabel("Result");
		resultLabelCombine.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		resultLabelCombine.setHorizontalAlignment(SwingConstants.CENTER);
		resultLabelCombine.setPreferredSize(new Dimension(100, 16));
		resultContainerPanelCombine.add(resultLabelCombine);

		JTextField resultFileTextFieldCombine = new JTextField();
		resultFileTextFieldCombine.setEditable(false);
		resultFileTextFieldCombine.setFont(new Font("Tahoma", Font.PLAIN, 16));
		resultFileTextFieldCombine.setBackground(Color.WHITE);
		resultContainerPanelCombine.add(resultFileTextFieldCombine);

		JButton resultBrowseBtnCombine = new JButton("Open");
		resultBrowseBtnCombine.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		resultContainerPanelCombine.add(resultBrowseBtnCombine);

		/* Type Action */
		encryptBtnCombine.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JRadioButton jrb = (JRadioButton) e.getSource();
				originalFileTextFieldCombine.setText("");
				resultFileTextFieldCombine.setText("");
				if (jrb.isSelected()) {
					actionBtn.setLabel("Encrypt");
					keyLabelCombine.setText("Public Key Path");
				}
			}
		});

		decryptBtnCombine.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JRadioButton jrb = (JRadioButton) e.getSource();
				originalFileTextFieldCombine.setText("");
				resultFileTextFieldCombine.setText("");
				if (jrb.isSelected()) {
					actionBtn.setLabel("Decrypt");
					keyLabelCombine.setText("Private Key Path");
				}
			}
		});

		JLabel sModeLabelCombine = new JLabel("Mode");
		sModeLabelCombine.setHorizontalAlignment(SwingConstants.CENTER);
		sModeLabelCombine.setFont(new Font("Tahoma", Font.BOLD, 16));
		sModeLabelCombine.setAlignmentX(0.5f);
		symContentPanelCombine.add(sModeLabelCombine);

		JComboBox sModeComboboxCombine = new JComboBox(new Object[] {});
		sModeComboboxCombine.setFont(new Font("Tahoma", Font.BOLD, 13));
		symContentPanelCombine.add(sModeComboboxCombine);

		JLabel sPaddingLabelCombine = new JLabel("Padding");
		sPaddingLabelCombine.setHorizontalAlignment(SwingConstants.CENTER);
		sPaddingLabelCombine.setFont(new Font("Tahoma", Font.BOLD, 16));
		symContentPanelCombine.add(sPaddingLabelCombine);

		JComboBox sPaddingComboboxCombine = new JComboBox(new Object[] {});
		sPaddingComboboxCombine.setFont(new Font("Tahoma", Font.BOLD, 13));
		symContentPanelCombine.add(sPaddingComboboxCombine);

		actionBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent event) {
				if (tabbedPane.getSelectedIndex() == 3) {
					String type = null;
					String original = null;
					String keyPath = keyTextFieldCombine.getText();
					if (fileRadioButtonCombine.isSelected()) {
						type = "file";
						original = originalFileTextFieldCombine.getText();
					}
					String sAlgorithmName = String.valueOf(sAlgorithmComboboxCombine.getSelectedItem());
					String sMode = String.valueOf(sModeComboboxCombine.getSelectedItem());
					String sPadding = String.valueOf(sPaddingComboboxCombine.getSelectedItem());
					String asAlgorithmName = String.valueOf(asAlgorithmComboboxCombine.getSelectedItem());
					String asMode = String.valueOf(asModeComboboxCombine.getSelectedItem());
					String asPadding = String.valueOf(asPaddingComboboxCombine.getSelectedItem());
					SymmetricAlgorithm sAlgo = new SymmetricAlgorithm(sAlgorithmName, sMode, sPadding);
					AsymmetricAlgorithm asAlgo = new AsymmetricAlgorithm(asAlgorithmName, asMode, asPadding);
					String value = null;
					if (encryptBtnCombine.isSelected() && actionBtn.getLabel().equals("Encrypt")) {
						/* __SET UP VALUE to setText in textField */
						try {
							value = combineSecurity.encryptionRSAWithSym(keyPath, sAlgo, asAlgo, original);
						} catch (IllegalBlockSizeException e) {
							JOptionPane.showMessageDialog(null, "Không thành công");
						} catch (BadPaddingException e) {
							JOptionPane.showMessageDialog(null, "Không thành công");
						} catch (NoSuchAlgorithmException e) {
							JOptionPane.showMessageDialog(null, "Thuật toán không hợp lệ");
						} catch (InvalidKeySpecException e) {
							JOptionPane.showMessageDialog(null, "Khoá không hợp lệ");
						} catch (NoSuchPaddingException e) {
							JOptionPane.showMessageDialog(null, "Padding không hợp lệ");
						} catch (IOException e) {
							JOptionPane.showMessageDialog(null, "Không thành công");
						}
					} else if (decryptBtnCombine.isSelected() && actionBtn.getLabel().equals("Decrypt")) {
						System.out.println("okkkk");
						value = combineSecurity.decryptionRSAWithSym(keyPath, sAlgo, asAlgo, original);
					}
					/* __SET VALUE for INPUT */
					if (type.equals("file")) {
						resultFileTextFieldCombine.setText(value);
					}
				}
			}
		});
		originalBrowseBtnCombine.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser jsc = new JFileChooser();
				jsc.setFileSelectionMode(JFileChooser.FILES_ONLY);
				int returnVal = jsc.showOpenDialog(null);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File f = jsc.getSelectedFile();
					originalFileTextFieldCombine.setText(f.getAbsolutePath());
				}
			}
		});
		resultBrowseBtnCombine.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					System.out.println(StringUtils.isNotEmpty(resultFileTextFieldCombine.getText()));
					if (StringUtils.isNotEmpty(resultFileTextFieldCombine.getText())
							&& fileRadioButtonCombine.isSelected()) {
						Desktop.getDesktop().open(new File(resultFileTextFieldCombine.getText()));
					} else {
						JOptionPane.showMessageDialog(null, "Không thể mở khi đư�?ng dẫn trống");
					}
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		sAlgorithmComboboxCombine.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JComboBox jcb = (JComboBox) e.getSource();
				Object algorithmName = jcb.getSelectedItem();
				AttributeCustomize attribute = sServicesCombine.get(algorithmName);
				Object[] modes = attribute.getMode();
				Object[] paddings = attribute.getPadding();
				if (modes != null) {
					sModeComboboxCombine.removeAllItems();
					for (Object mode : modes) {
						sModeComboboxCombine.addItem(mode);
					}
				}
				if (paddings != null) {
					sPaddingComboboxCombine.removeAllItems();
					for (Object padding : paddings) {
						sPaddingComboboxCombine.addItem(padding);
					}
				}
			}
		});
		sAlgorithmComboboxCombine.setSelectedIndex(0);

		asAlgorithmComboboxCombine.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JComboBox jcb = (JComboBox) e.getSource();
				Object algorithmName = jcb.getSelectedItem();
				AttributeCustomize attribute = asServicesCombine.get(algorithmName);
				Object[] modes = attribute.getMode();
				Object[] paddings = attribute.getPadding();
				if (modes != null) {
					asModeComboboxCombine.removeAllItems();
					for (Object mode : modes) {
						asModeComboboxCombine.addItem(mode);
					}
				}
				if (paddings != null) {
					asPaddingComboboxCombine.removeAllItems();
					for (Object padding : paddings) {
						asPaddingComboboxCombine.addItem(padding);
					}
				}
			}
		});
		asAlgorithmComboboxCombine.setSelectedIndex(0);
	}
}
