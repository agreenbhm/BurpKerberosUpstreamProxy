package com.agreenbhm.kerberosupstreamextension;

import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.SwingWorker;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.persistence.PersistedObject;

public class KerberosUpstreamExtension implements BurpExtension {

    private MontoyaApi api;
    private Http http;
    private Logging logging;
    private UserInterface userInterface;
    private Extension extension;
    private ProxyChain proxyChain;
    private KerberosAuthenticator authenticator;

    public static void main(String[] args) {

        KerberosAuthenticator authenticator = new KerberosAuthenticator("administrator",
                "P@$$w0rd".toCharArray(), "LAB.LOCAL", "dc.lab.local", "squid.lab.local", "/etc/krb5.conf");
        if (!authenticator.isInitialized) {
            System.out.println("Authenticator not initialized");
            return;
        }
        ProxyChain proxyChain = new ProxyChain();
        proxyChain.upstreamProxyPortInt = 3128;
        proxyChain.start(authenticator);
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        logging = api.logging();
        extension = api.extension();
        extension.setName("KerberosUpstreamExtension");
        extension.registerUnloadingHandler(new MyExtensionUnloadingHandler());
        userInterface = api.userInterface();

        PersistedObject savedExtensionData = api.persistence().extensionData();

        userInterface.registerSuiteTab("Kerberos Upstream Proxy", new KerberosUpstreamExtensionTab(savedExtensionData));

        logging.logToOutput("KerberosUpstreamExtension initialized");
    }

    private class MyExtensionUnloadingHandler implements ExtensionUnloadingHandler {
        @Override
        public void extensionUnloaded() {
            if (proxyChain != null) {
                proxyChain.stop();
            }
            logging.logToOutput("Extension was unloaded.");
        }
    }

    private class KerberosUpstreamExtensionTab extends JPanel {
        public KerberosUpstreamExtensionTab(PersistedObject savedExtensionData) {
            setLayout(new GridBagLayout());
            GridBagConstraints c = new GridBagConstraints();
            c.gridx = 0;
            c.gridy = 0;

            add(new JLabel("Realm"), c);
            c.gridx++;
            JTextField realmField = new JTextField("", 25);
            realmField.setText("LAB.LOCAL");
            add(realmField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("KDC"), c);
            c.gridx++;
            JTextField kdcField = new JTextField("", 25);
            kdcField.setText("dc.lab.local");
            add(kdcField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("Upstream Proxy Host"), c);
            c.gridx++;
            JTextField upstreamProxyHostField = new JTextField("", 25);
            upstreamProxyHostField.setText("squid.lab.local");
            add(upstreamProxyHostField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("Upstream Proxy Port"), c);
            c.gridx++;
            JTextField upstreamProxyPortField = new JTextField("", 25);
            upstreamProxyPortField.setText("3128");
            add(upstreamProxyPortField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("Local Proxy Port"), c);
            c.gridx++;
            JTextField localProxyPorTextField = new JTextField("", 25);
            localProxyPorTextField.setText("8000");
            add(localProxyPorTextField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("krb5.conf Path"), c);
            c.gridx++;
            JTextField krb5ConfField = new JTextField("", 25);
            krb5ConfField.setText("/etc/krb5.conf");
            add(krb5ConfField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("Username"), c);
            c.gridx++;
            JTextField usernameField = new JTextField("", 25);
            usernameField.setText("administrator");
            add(usernameField, c);
            c.gridx = 0;
            c.gridy++;

            add(new JLabel("Password"), c);
            c.gridx++;
            JPasswordField passwordField = new JPasswordField("", 25);
            // passwordField.setText("P@$$w0rd");
            add(passwordField, c);
            c.gridx = 0;
            c.gridy++;

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
                        int upstreamProxyPortInt = Integer.parseInt(upstreamProxyPortField.getText());
                        int localProxyPortInt = Integer.parseInt(localProxyPorTextField.getText());
                        String krb5conf = krb5ConfField.getText();

                        if(username.isEmpty() || password.length == 0 || realm.isEmpty() || kdc.isEmpty() || upstreamProxyHost.isEmpty() || krb5conf.isEmpty()) {
                            statusField.setText("Error: Missing required fields");
                            return null;
                        }
                        
                        startProxyButton.setEnabled(false);
                        stopProxyButton.setEnabled(false);

                        statusField.setText("Authenticating...");
                        try {
                            authenticator = new KerberosAuthenticator(username, password, realm, kdc, upstreamProxyHost,
                                    krb5conf);
                            if (!authenticator.isInitialized) {
                                statusField.setText("Error: Authenticator not initialized");
                                return null;
                            }
                            statusField.setText("Authenticated; Creating Proxy Chain...");
                            proxyChain = new ProxyChain();
                            proxyChain.upstreamProxyPortInt = upstreamProxyPortInt;
                            proxyChain.localProxyPortInt = localProxyPortInt;
                            proxyChain.upstreamProxyHost = upstreamProxyHost;
                            statusField.setText("Proxy Chain Created; Starting...");
                            proxyChain.start(authenticator);
                            statusField.setText("Proxy Started");
                        } catch (Exception ex) {
                            logging.logToOutput("Error: " + ex.getMessage());
                            statusField.setText("Error: " + ex.getMessage());
                        }
                        return null;
                    }

                    @Override
                    protected void done() {
                        if (authenticator.isInitialized && proxyChain.isStarted) {
                            stopProxyButton.setEnabled(true);
                            startProxyButton.setEnabled(false);
                        } else {
                            startProxyButton.setEnabled(true);
                            stopProxyButton.setEnabled(false);
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
                            logging.logToOutput("Error: " + ex.getMessage());
                            statusField.setText("Error: " + ex.getMessage());
                        }
                        return null;
                    }

                    @Override
                    protected void done() {
                        if (proxyChain.isStarted) {
                            stopProxyButton.setEnabled(true);
                            startProxyButton.setEnabled(false);
                        } else {
                            stopProxyButton.setEnabled(false);
                            startProxyButton.setEnabled(true);
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

                        } catch (Exception ex) {
                            logging.logToOutput("Error: " + ex.getMessage());
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
                            realmField.setText("");
                            kdcField.setText("");
                            upstreamProxyHostField.setText("");
                            upstreamProxyPortField.setText("");
                            localProxyPorTextField.setText("");
                            krb5ConfField.setText("");
                            usernameField.setText("");
                            passwordField.setText("");
                        } catch (Exception ex) {
                            logging.logToOutput("Error: " + ex.getMessage());
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

            c.weighty = 1;
            add(new JLabel(""), c);
        }
    }

}
