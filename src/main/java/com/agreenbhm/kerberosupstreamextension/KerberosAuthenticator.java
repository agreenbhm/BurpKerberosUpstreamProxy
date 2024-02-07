package com.agreenbhm.kerberosupstreamextension;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import org.ietf.jgss.*;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class KerberosAuthenticator {

    private GSSManager manager;
    private Subject subject;
    private String username;
    private char[] password;
    private String realm;
    private String kdc;
    private String spn;
    private String upstreamProxyHost;
    private String krb5conf;
    public boolean isInitialized = false;

    public KerberosAuthenticator(String username, char[] password, String realm, String kdc, String upstreamProxyHost,
            String krb5conf) {
        this.username = username;
        this.password = password;
        this.realm = realm;
        this.kdc = kdc;
        this.upstreamProxyHost = upstreamProxyHost;
        this.krb5conf = krb5conf;

        this.isInitialized = initializeSubject();
        if (this.isInitialized) {
            manager = GSSManager.getInstance();
        }
    }

    private boolean initializeSubject() {

        CreateKrb5Conf.CreateKrb5Conf(this.krb5conf);

        System.setProperty("java.security.krb5.realm", this.realm);
        System.setProperty("java.security.krb5.kdc", this.kdc);
        System.setProperty("java.security.krb5.conf", this.krb5conf);
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "true");
        // System.setProperty("sun.security.krb5.debug", "true");
        // System.setProperty("sun.security.spnego.debug", "true");
        System.setProperty("java.net.preferIPv4Stack", "true");

        Configuration config = new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(
                    String name) {

                Map<String, Object> map = new HashMap<String, Object>();
                map.put("doNotPrompt", "false");
                map.put("useTicketCache", "false");
                map.put("refreshKrb5Config", "true");

                return new AppConfigurationEntry[] { new AppConfigurationEntry(
                        "com.sun.security.auth.module.Krb5LoginModule",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                        map) };
            }

            @Override
            public void refresh() {
                // ignored
            }
        };

        Configuration.setConfiguration(config);

        spn = this.username + "@" + this.realm;
        AuthCallbackHandler handler = new AuthCallbackHandler(this.spn, this.password);

        try {
            LoginContext lc = new LoginContext("KrbLogin", handler);
            lc.login();
            subject = lc.getSubject();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;

    }

    public String getNewToken() {
        try {
            GSSName serverName = manager.createName("HTTP@" + this.upstreamProxyHost, GSSName.NT_HOSTBASED_SERVICE);
            GSSContext context = manager.createContext(serverName, null, null, GSSContext.DEFAULT_LIFETIME);

            byte[] token = new byte[0];
            // Use Subject.doAs to ensure the correct Kerberos credentials are used
            byte[] newToken = Subject.doAs(subject, (java.security.PrivilegedExceptionAction<byte[]>) () -> context
                    .initSecContext(token, 0, token.length));

            return Base64.getEncoder().encodeToString(newToken);
        } catch (Exception e) {
            e.printStackTrace();
            // Handle exception appropriately
            return null;
        }
    }

    public class AuthCallbackHandler implements CallbackHandler {
        private String spn;
        private char[] password;

        public AuthCallbackHandler(String spn, char[] password) {
            this.spn = spn;
            this.password = password;
        }

        @Override
        public void handle(Callback[] callbacks)
                throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    NameCallback nameCallback = (NameCallback) callback;
                    nameCallback.setName(this.spn);
                } else if (callback instanceof PasswordCallback) {
                    PasswordCallback passwordCallback = (PasswordCallback) callback;
                    passwordCallback.setPassword(this.password);
                } else {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        }
    };

}
