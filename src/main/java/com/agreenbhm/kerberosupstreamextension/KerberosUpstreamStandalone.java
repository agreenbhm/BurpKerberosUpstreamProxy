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

import org.apache.commons.cli.*;

public class KerberosUpstreamStandalone {

    private ProxyChain proxyChain;
    private KerberosAuthenticator authenticator;
    private static boolean debugBuild = false;

    public static void main(String[] args) {
        System.setProperty("java.net.preferIPv4Stack", "true");
        KerberosAuthenticator authenticator;

        Options options = new Options();
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;

        if (debugBuild) {
            authenticator = new KerberosAuthenticator("administrator",
                    "P@$$w0rd".toCharArray(), "LAB.LOCAL", "dc.lab.local", "squid.lab.local", "/etc/krb5.conf");
        } else {

            options.addOption(Option.builder("u").longOpt("username").required(true).hasArg().desc("Username").build());
            options.addOption(Option.builder("p").longOpt("password").required(true).hasArg().desc("Password").build());
            options.addOption(Option.builder("r").longOpt("realm").required(true).hasArg().desc("Realm").build());
            options.addOption(Option.builder("k").longOpt("kdc").required(true).hasArg().desc("KDC").build());
            options.addOption(Option.builder("h").longOpt("upstream-proxy").required(true).hasArg().desc("Upstream Proxy Host").build());
            options.addOption(Option.builder("i").longOpt("upstream-proxy-port").required(true).hasArg().desc("Upstream Proxy Port").build());
            options.addOption(Option.builder("l").longOpt("local-proxy-port").required(true).hasArg().desc("Local Proxy Port").build());
            options.addOption(Option.builder("c").longOpt("krb5-conf").required(true).hasArg().desc("krb5.conf Path").build());
            options.addOption(Option.builder("a").longOpt("require-local-auth").required(false).desc("Require Local Auth").build());
            options.addOption(Option.builder("v").longOpt("local-auth-value").required(false).hasArg().desc("Local Auth Value").build());

            try {
                cmd = parser.parse(options, args);
                authenticator = new KerberosAuthenticator(cmd.getOptionValue("username"),
                        cmd.getOptionValue("password").toCharArray(),
                        cmd.getOptionValue("realm"), cmd.getOptionValue("kdc"), cmd.getOptionValue("upstream-proxy"),
                        cmd.getOptionValue("krb5-conf"));
            } catch (ParseException e) {
                System.out.println(e.getMessage());
                formatter.printHelp("KerberosUpstreamExtension", options);
                System.exit(1);
                return;
            }

        }

        if (!authenticator.isInitialized) {
            System.out.println("Error: Authenticator not initialized");
            System.exit(1);
            return;
        }

        ProxyChain proxyChain = new ProxyChain();
        if (debugBuild) {
            proxyChain.upstreamProxyPortInt = 3128;
            proxyChain.localProxyPortInt = 8000;
            proxyChain.upstreamProxyHost = "squid.lab.local";
        }else{
            if (cmd != null) {
                proxyChain.upstreamProxyHost = cmd.getOptionValue("upstream-proxy");
                proxyChain.upstreamProxyPortInt = Integer.parseInt(cmd.getOptionValue("upstream-proxy-port"));
                proxyChain.localProxyPortInt = Integer.parseInt(cmd.getOptionValue("local-proxy-port"));
                if(cmd.hasOption("a") && cmd.hasOption("v") && !cmd.getOptionValue("v").isBlank()){
                    proxyChain.requireLocalAuth = true;
                    proxyChain.localAuthValue = cmd.getOptionValue("v");
                }else if(cmd.hasOption("a") && (!cmd.hasOption("v") || cmd.getOptionValue("v").isBlank())){
                    System.out.println("Error: Local Auth enabled but no Local Auth Value provided");
                    System.exit(1);
                    return;
                }
            }
        }
        proxyChain.start(authenticator);
    }
}
