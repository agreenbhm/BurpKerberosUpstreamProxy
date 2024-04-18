package com.agreenbhm.kerberosupstreamextension;

import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.SwingWorker;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.core.Registration;

import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.persistence.PersistedObject;

import java.security.SecureRandom;
import java.util.Random;
import java.util.stream.Collectors;
import java.net.InetSocketAddress;


public class KerberosUpstreamExtension implements BurpExtension {

    private MontoyaApi api;
    private Logging logging;
    private UserInterface userInterface;
    private Extension extension;
    private ProxyChain proxyChain;
    private KerberosAuthenticator authenticator;
    private static boolean debugBuild = false;
    private boolean debug = false;
    private ExtensionLogging extensionLogging;


    @Override
    public void initialize(MontoyaApi initializeAPI) {
        System.setProperty("java.net.preferIPv4Stack", "true");
        api = initializeAPI;
        logging = api.logging();
        extensionLogging = new ExtensionLogging(api.logging());
        extension = api.extension();
        extension.setName("KerberosUpstreamExtension");
        extension.registerUnloadingHandler(new MyExtensionUnloadingHandler());
        userInterface = api.userInterface();

        PersistedObject savedExtensionData = api.persistence().extensionData();

        userInterface.registerSuiteTab("Kerberos Upstream Proxy", new KerberosUpstreamExtensionTab(savedExtensionData));
        extensionLogging.logToOutput("KerberosUpstreamExtension initialized");
    }

    private class MyExtensionUnloadingHandler implements ExtensionUnloadingHandler {
        @Override
        public void extensionUnloaded() {
            if (proxyChain != null) {
                proxyChain.stop();
            }
            extensionLogging.logToOutput("Extension was unloaded.");
        }
    }

    private class KerberosUpstreamExtensionTab extends JPanel {
        Registration httpHandlerRegistration;

        public KerberosUpstreamExtensionTab(PersistedObject savedExtensionData) {

            setLayout(new GridBagLayout());
            GridBagConstraints c = new GridBagConstraints();
            c.gridx = 0;
            c.gridy = 0;

            add(new JLabel("Realm"), c);
            c.gridx++;
            JTextField realmField = new JTextField("", 25);
            add(realmField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("KDC"), c);
            c.gridx++;
            JTextField kdcField = new JTextField("", 25);
            add(kdcField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("Upstream Proxy Host"), c);
            c.gridx++;
            JTextField upstreamProxyHostField = new JTextField("", 25);
            add(upstreamProxyHostField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("Upstream Proxy Port"), c);
            c.gridx++;
            JTextField upstreamProxyPortField = new JTextField("", 25);
            add(upstreamProxyPortField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("Local Proxy Port"), c);
            c.gridx++;
            JTextField localProxyPorTextField = new JTextField("", 25);
            add(localProxyPorTextField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("krb5.conf Path"), c);
            c.gridx++;
            JTextField krb5ConfField = new JTextField("", 25);
            add(krb5ConfField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("Username"), c);
            c.gridx++;
            JTextField usernameField = new JTextField("", 25);
            add(usernameField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("Password"), c);
            c.gridx++;
            JPasswordField passwordField = new JPasswordField("", 25);
            add(passwordField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("Require Local Auth"), c);
            c.gridx++;
            JCheckBox requireLocalAuthCheckBox = new JCheckBox();
            requireLocalAuthCheckBox.setSelected(false);
            add(requireLocalAuthCheckBox, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("Local Auth Password"), c);
            c.gridx++;
            JTextField localAuthValueField = new JTextField(RandomStringGenerator.generateSecureHeaderString(), 25);
            localAuthValueField.setEnabled(false);
            add(localAuthValueField, c);
            c.gridx = 0;
            c.gridy++;

            requireLocalAuthCheckBox.addActionListener(e -> {
                if (requireLocalAuthCheckBox.isSelected()) {
                    localAuthValueField.setEnabled(true);
                } else {
                    localAuthValueField.setEnabled(false);
                }
            });

            if (savedExtensionData.getString("REALM") != null) {
                realmField.setText(savedExtensionData.getString("REALM"));
            }
            if (savedExtensionData.getString("KDC") != null) {
                kdcField.setText(savedExtensionData.getString("KDC"));
            }
            if (savedExtensionData.getString("UPSTREAM_PROXY_HOST") != null) {
                upstreamProxyHostField.setText(savedExtensionData.getString("UPSTREAM_PROXY_HOST"));
            }
            if (savedExtensionData.getString("UPSTREAM_PROXY_PORT") != null) {
                upstreamProxyPortField.setText(savedExtensionData.getString("UPSTREAM_PROXY_PORT"));
            }
            if (savedExtensionData.getString("LOCAL_PROXY_PORT") != null) {
                localProxyPorTextField.setText(savedExtensionData.getString("LOCAL_PROXY_PORT"));
            }
            if (savedExtensionData.getString("KRB5_CONF") != null) {
                krb5ConfField.setText(savedExtensionData.getString("KRB5_CONF"));
            }
            if (savedExtensionData.getString("USERNAME") != null) {
                usernameField.setText(savedExtensionData.getString("USERNAME"));
            }
            if (savedExtensionData.getBoolean("USE_SECURE_HEADER") != null) {
                requireLocalAuthCheckBox.setSelected(savedExtensionData.getBoolean("USE_SECURE_HEADER"));
            }
            if (savedExtensionData.getString("SECURE_HEADER_STRING") != null) {
                localAuthValueField.setText(savedExtensionData.getString("SECURE_HEADER_STRING"));
            }

            c.gridy += 10;
            add(new JLabel("Status"), c);
            c.gridx++;
            JLabel statusField = new JLabel("Stopped");
            add(statusField, c);
            c.gridx = 0;
            c.gridy++;

            c.anchor = GridBagConstraints.SOUTHWEST;
            JButton startProxyButton = new JButton("Start Proxy");
            add(startProxyButton, c);
            c.gridx++;

            JButton stopProxyButton = new JButton("Stop Proxy");
            stopProxyButton.setEnabled(false);
            add(stopProxyButton, c);
            c.gridx++;

            startProxyButton.addActionListener(e -> {
                SwingWorker<Void, Void> authWorker = new SwingWorker<Void, Void>() {
                    @Override
                    protected Void doInBackground() throws Exception {
                        String username = usernameField.getText();
                        char[] password = passwordField.getPassword();
                        String realm = realmField.getText();
                        String kdc = kdcField.getText();
                        String upstreamProxyHost = upstreamProxyHostField.getText();
                        int upstreamProxyPortInt = upstreamProxyPortField.getText().isEmpty() ? 0
                                : Integer.parseInt(upstreamProxyPortField.getText());
                        int localProxyPortInt = localProxyPorTextField.getText().isEmpty() ? 0
                                : Integer.parseInt(localProxyPorTextField.getText());
                        String krb5conf = krb5ConfField.getText();
                        boolean requireLocalAuth = requireLocalAuthCheckBox.isSelected();
                        String localAuthValue = localAuthValueField.getText();

                        if (username.isEmpty() || password.length == 0 || realm.isEmpty() || kdc.isEmpty()
                                || upstreamProxyHost.isEmpty() || krb5conf.isEmpty()
                                || (requireLocalAuth && localAuthValue.isEmpty())) {
                            statusField.setText("Error: Missing required fields");
                            return null;
                        }

                        startProxyButton.setEnabled(false);
                        stopProxyButton.setEnabled(false);

                        statusField.setText("Authenticating...");
                        try {
                            authenticator = new KerberosAuthenticator(username, password, realm, kdc, upstreamProxyHost,
                                    krb5conf, extensionLogging);
                            if (!authenticator.isInitialized) {
                                statusField.setText("Error: Authenticator not initialized");
                                return null;
                            }
                            statusField.setText("Authenticated; Creating Proxy Chain...");
                            proxyChain = new ProxyChain(extensionLogging);
                            proxyChain.upstreamProxyPortInt = upstreamProxyPortInt;
                            proxyChain.localProxySocket = new InetSocketAddress("127.0.0.1", localProxyPortInt);
                            proxyChain.upstreamProxyHost = upstreamProxyHost;
                            proxyChain.requireLocalAuth = requireLocalAuth;
                            proxyChain.localAuthValue = localAuthValue;
                            statusField.setText("Proxy Chain Created; Starting...");
                            proxyChain.start(authenticator);
                            statusField.setText("Proxy Started");

                        } catch (Exception ex) {
                            extensionLogging.logToError("Error: " + ex.getMessage());
                            statusField.setText("Error: " + ex.getMessage());

                        }
                        return null;
                    }

                    @Override
                    protected void done() {
                        if (authenticator.isInitialized && proxyChain.isStarted) {
                            stopProxyButton.setEnabled(true);
                            startProxyButton.setEnabled(false);
                            kdcField.setEnabled(false);
                            realmField.setEnabled(false);
                            upstreamProxyHostField.setEnabled(false);
                            upstreamProxyPortField.setEnabled(false);
                            localProxyPorTextField.setEnabled(false);
                            krb5ConfField.setEnabled(false);
                            usernameField.setEnabled(false);
                            passwordField.setEnabled(false);
                            requireLocalAuthCheckBox.setEnabled(false);
                            localAuthValueField.setEnabled(false);
                        } else {
                            startProxyButton.setEnabled(true);
                            stopProxyButton.setEnabled(false);
                            kdcField.setEnabled(true);
                            realmField.setEnabled(true);
                            upstreamProxyHostField.setEnabled(true);
                            upstreamProxyPortField.setEnabled(true);
                            localProxyPorTextField.setEnabled(true);
                            krb5ConfField.setEnabled(true);
                            usernameField.setEnabled(true);
                            passwordField.setEnabled(true);
                            requireLocalAuthCheckBox.setEnabled(true);
                            localAuthValueField.setEnabled(true);
                        }
                    }
                };
                authWorker.execute();
            });

            stopProxyButton.addActionListener(e -> {
                SwingWorker<Void, Void> teardownWorker = new SwingWorker<Void, Void>() {
                    @Override
                    protected Void doInBackground() throws Exception {

                        stopProxyButton.setEnabled(false);
                        startProxyButton.setEnabled(false);
                        try {
                            proxyChain.stop();
                            statusField.setText("Proxy Stopped");
                        } catch (Exception ex) {
                            extensionLogging.logToOutput("Error: " + ex.getMessage());
                            statusField.setText("Error: " + ex.getMessage());
                        }
                        return null;
                    }

                    @Override
                    protected void done() {
                        if (proxyChain.isStarted) {
                            stopProxyButton.setEnabled(true);
                            startProxyButton.setEnabled(false);
                            stopProxyButton.setEnabled(true);
                            startProxyButton.setEnabled(false);
                            kdcField.setEnabled(false);
                            realmField.setEnabled(false);
                            upstreamProxyHostField.setEnabled(false);
                            upstreamProxyPortField.setEnabled(false);
                            localProxyPorTextField.setEnabled(false);
                            krb5ConfField.setEnabled(false);
                            usernameField.setEnabled(false);
                            passwordField.setEnabled(false);
                            requireLocalAuthCheckBox.setEnabled(false);
                            localAuthValueField.setEnabled(false);
                        } else {
                            stopProxyButton.setEnabled(false);
                            startProxyButton.setEnabled(true);
                            kdcField.setEnabled(true);
                            realmField.setEnabled(true);
                            upstreamProxyHostField.setEnabled(true);
                            upstreamProxyPortField.setEnabled(true);
                            localProxyPorTextField.setEnabled(true);
                            krb5ConfField.setEnabled(true);
                            usernameField.setEnabled(true);
                            passwordField.setEnabled(true);
                            requireLocalAuthCheckBox.setEnabled(true);
                            localAuthValueField.setEnabled(true);
                        }
                    }
                };
                teardownWorker.execute();
            });

            JButton saveSettingsButton = new JButton("Save Settings");
            saveSettingsButton.addActionListener(e -> {
                SwingWorker<Void, Void> saveSettingsWorker = new SwingWorker<Void, Void>() {
                    @Override
                    protected Void doInBackground() throws Exception {
                        try {
                            savedExtensionData.setString("REALM", realmField.getText());
                            savedExtensionData.setString("KDC", kdcField.getText());
                            savedExtensionData.setString("UPSTREAM_PROXY_HOST", upstreamProxyHostField.getText());
                            savedExtensionData.setString("UPSTREAM_PROXY_PORT", upstreamProxyPortField.getText());
                            savedExtensionData.setString("LOCAL_PROXY_PORT", localProxyPorTextField.getText());
                            savedExtensionData.setString("KRB5_CONF", krb5ConfField.getText());
                            savedExtensionData.setString("USERNAME", usernameField.getText());
                            savedExtensionData.setBoolean("USE_SECURE_HEADER", requireLocalAuthCheckBox.isSelected());
                            savedExtensionData.setString("SECURE_HEADER_STRING", localAuthValueField.getText());

                        } catch (Exception ex) {
                            extensionLogging.logToError("Error: " + ex.getMessage());
                            statusField.setText("Error saving settings");
                        }
                        return null;
                    }

                    @Override
                    protected void done() {
                        statusField.setText("Settings Saved");
                    }
                };
                saveSettingsWorker.execute();

            });
            add(saveSettingsButton, c);
            c.gridx++;

            JButton clearSettingsButton = new JButton("Clear Settings");
            clearSettingsButton.addActionListener(e -> {
                SwingWorker<Void, Void> clearSettingsWorker = new SwingWorker<Void, Void>() {
                    @Override
                    protected Void doInBackground() throws Exception {
                        try {
                            savedExtensionData.deleteString("REALM");
                            savedExtensionData.deleteString("KDC");
                            savedExtensionData.deleteString("UPSTREAM_PROXY_HOST");
                            savedExtensionData.deleteString("UPSTREAM_PROXY_PORT");
                            savedExtensionData.deleteString("LOCAL_PROXY_PORT");
                            savedExtensionData.deleteString("KRB5_CONF");
                            savedExtensionData.deleteString("USERNAME");
                            savedExtensionData.deleteBoolean("USE_SECURE_HEADER");
                            savedExtensionData.deleteString("SECURE_HEADER_STRING");
                            realmField.setText("");
                            kdcField.setText("");
                            upstreamProxyHostField.setText("");
                            upstreamProxyPortField.setText("");
                            localProxyPorTextField.setText("");
                            krb5ConfField.setText("");
                            usernameField.setText("");
                            passwordField.setText("");
                            requireLocalAuthCheckBox.setEnabled(true);
                            requireLocalAuthCheckBox.setSelected(false);
                            localAuthValueField.setEnabled(false);
                            localAuthValueField.setText(RandomStringGenerator.generateSecureHeaderString());

                            if (debug) {
                                realmField.setText("LAB.LOCAL");
                                kdcField.setText("dc.lab.local");
                                upstreamProxyHostField.setText("squid.lab.local");
                                upstreamProxyPortField.setText("3128");
                                localProxyPorTextField.setText("8000");
                                krb5ConfField.setText("/etc/krb5.conf");
                                usernameField.setText("administrator");
                                passwordField.setText("P@$$w0rd");
                                requireLocalAuthCheckBox.setEnabled(true);
                                requireLocalAuthCheckBox.setSelected(true);
                                localAuthValueField.setEnabled(true);
                                localAuthValueField.setText("secure");
                            }

                        } catch (Exception ex) {
                            extensionLogging.logToError("Error: " + ex.getMessage());
                            statusField.setText("Error clearing settings");
                        }
                        return null;
                    }

                    @Override
                    protected void done() {
                        statusField.setText("Settings Cleared");
                    }
                };
                clearSettingsWorker.execute();
            });
            add(clearSettingsButton, c);
            c.gridx++;

            JCheckBox debugCheckBox = new JCheckBox("Debug");
            debugCheckBox.addActionListener(e -> {
                debug = debugCheckBox.isSelected();
            });
            if (debugBuild) {
                add(debugCheckBox, c);
                if (debug) {
                    debugCheckBox.setSelected(true);
                }
            }

            c.gridx++;

            c.weighty = 1;
            add(new JLabel(""), c);
        }
    }

}

class RandomStringGenerator {
    public static String generateSecureHeaderString() {
        Random random = new SecureRandom();
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        String randomString = random.ints(16, 0, characters.length())
                .mapToObj(i -> String.valueOf(characters.charAt(i)))
                .collect(Collectors.joining());
        return randomString;
    }
}
