package com.agreenbhm.kerberosupstreamextension;

import org.apache.commons.cli.*;
import java.net.InetSocketAddress;

public class KerberosUpstreamStandalone {

    private static boolean debugBuild = false;

    public static void main(String[] args) {
        System.setProperty("java.net.preferIPv4Stack", "true");
        KerberosAuthenticator authenticator;
        ExtensionLogging extensionLogging = new ExtensionLogging();

        Options options = new Options();
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;

        if (debugBuild) {
            authenticator = new KerberosAuthenticator("administrator",
                    "P@$$w0rd".toCharArray(), "LAB.LOCAL", "dc.lab.local", "squid.lab.local", "/etc/krb5.conf", extensionLogging);
        } else {

            options.addOption(Option.builder("u").longOpt("username").required(true).hasArg().desc("Username").build());
            options.addOption(Option.builder("p").longOpt("password").required(true).hasArg().desc("Password").build());
            options.addOption(Option.builder("r").longOpt("realm").required(true).hasArg().desc("Realm").build());
            options.addOption(Option.builder("k").longOpt("kdc").required(true).hasArg().desc("KDC").build());
            options.addOption(Option.builder("h").longOpt("upstream-proxy").required(true).hasArg().desc("Upstream Proxy Host").build());
            options.addOption(Option.builder("i").longOpt("upstream-proxy-port").required(true).hasArg().desc("Upstream Proxy Port").build());
            options.addOption(Option.builder("l").longOpt("local-proxy-port").required(true).hasArg().desc("Local Proxy Port").build());
            options.addOption(Option.builder("s").longOpt("local-proxy-ip").required(false).hasArg().desc("Local Proxy IP").build());
            options.addOption(Option.builder("c").longOpt("krb5-conf").required(true).hasArg().desc("krb5.conf Path").build());
            options.addOption(Option.builder("a").longOpt("require-local-auth").required(false).desc("Require Local Auth").build());
            options.addOption(Option.builder("v").longOpt("local-auth-value").required(false).hasArg().desc("Local Auth Value").build());

            try {
                cmd = parser.parse(options, args);
                authenticator = new KerberosAuthenticator(cmd.getOptionValue("username"),
                        cmd.getOptionValue("password").toCharArray(),
                        cmd.getOptionValue("realm"), cmd.getOptionValue("kdc"), cmd.getOptionValue("upstream-proxy"),
                        cmd.getOptionValue("krb5-conf"), extensionLogging);
            } catch (ParseException e) {
                extensionLogging.logToError(e.getMessage());
                formatter.printHelp("KerberosUpstreamExtension", options);
                System.exit(1);
                return;
            }

        }

        if (!authenticator.isInitialized) {
            extensionLogging.logToError("Error: Authenticator not initialized");
            System.exit(1);
            return;
        }

        ProxyChain proxyChain = new ProxyChain(extensionLogging);
        if (debugBuild) {
            proxyChain.upstreamProxyPortInt = 3128;
            proxyChain.upstreamProxyHost = "squid.lab.local";
            proxyChain.localProxySocket = new InetSocketAddress("127.0.0.1", 8000);
        }else{
            if (cmd != null) {
                proxyChain.upstreamProxyHost = cmd.getOptionValue("upstream-proxy");
                proxyChain.upstreamProxyPortInt = Integer.parseInt(cmd.getOptionValue("upstream-proxy-port"));
                if(cmd.hasOption("s") && !cmd.getOptionValue("s").isBlank()){
                    proxyChain.localProxySocket = new InetSocketAddress(cmd.getOptionValue("local-proxy-ip"), Integer.parseInt(cmd.getOptionValue("local-proxy-port")));
                }else{
                    proxyChain.localProxySocket = new InetSocketAddress("127.0.0.1", Integer.parseInt(cmd.getOptionValue("local-proxy-port")));
                }
                if(cmd.hasOption("a") && cmd.hasOption("v") && !cmd.getOptionValue("v").isBlank()){
                    proxyChain.requireLocalAuth = true;
                    proxyChain.localAuthValue = cmd.getOptionValue("v");
                }else if(cmd.hasOption("a") && (!cmd.hasOption("v") || cmd.getOptionValue("v").isBlank())){
                    extensionLogging.logToError("Error: Local Auth enabled but no Local Auth Value provided");
                    System.exit(1);
                    return;
                }
            }
        }
        proxyChain.start(authenticator);
    }
}
