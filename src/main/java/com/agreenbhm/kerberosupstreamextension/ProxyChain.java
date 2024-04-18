package com.agreenbhm.kerberosupstreamextension;

import org.littleshoot.proxy.*;
import org.littleshoot.proxy.impl.DefaultHttpProxyServer;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpObject;

import java.net.InetSocketAddress;
import java.util.Base64;

import javax.net.ssl.SSLEngine;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.HttpHeaders;

public class ProxyChain {

    private KerberosAuthenticator authenticator;
    private HttpProxyServer firstProxy;
    int upstreamProxyPortInt;
    InetSocketAddress localProxySocket;
    String upstreamProxyHost;
    boolean isStarted = false;
    boolean requireLocalAuth;
    String localAuthValue;
    ExtensionLogging extensionLogging;
    
    public ProxyChain(ExtensionLogging extensionLogging) {
        this.extensionLogging = extensionLogging;
    }

    private class MyChainedProxy implements ChainedProxy {
        @Override
        public InetSocketAddress getChainedProxyAddress() {
            // Address of the external proxy
            //extensionLogging.logToOutput("Creating chained proxy to " + upstreamProxyHost + ":"
            //        + Integer.toString(upstreamProxyPortInt));
            return new InetSocketAddress(upstreamProxyHost, upstreamProxyPortInt);
        }
        @Override
        public SSLEngine newSslEngine() {
            // Optional: Implement if SSL support is needed
            extensionLogging.logToError("SSL engine not implemented");
            throw new UnsupportedOperationException("SSL engine not implemented");
        }

        @Override
        public SSLEngine newSslEngine(String peerHost, int peerPort) {
            // Optional: Implement if SSL support is needed for specific host and port
            extensionLogging.logToError("SSL engine for specific host not implemented");
            throw new UnsupportedOperationException("SSL engine for specific host not implemented");
        }

        @Override
        public InetSocketAddress getLocalAddress() {
            // Optional: Implement to specify a local address
            return null; // Use system default
        }

        @Override
        public TransportProtocol getTransportProtocol() {
            // Specify the transport protocol
            return TransportProtocol.TCP; // Default TCP, implement as needed
        }

        @Override
        public boolean requiresEncryption() {
            // Specify if encryption is required
            return false; // Default false, update as needed
        }

        @Override
        public void filterRequest(HttpObject httpObject) {
            // Optional: Implement to filter/modifiy requests
        }

        @Override
        public void connectionSucceeded() {
            //extensionLogging.logToOutput("Connected to upstream proxy");
            // Optional: Implement to handle successful connection events
        }

        @Override
        public void connectionFailed(Throwable cause) {
            extensionLogging.logToError("Connection failed: " + cause.getMessage());
            // Optional: Implement to handle connection failure events
        }

        @Override
        public void disconnected() {
            //extensionLogging.logToOutput("Disconnected from upstream proxy");
            // Optional: Implement to handle disconnection events
        }

        // Implement other methods as necessary, default no-op implementations can be
        // used for simplicity
    }

    public void start(KerberosAuthenticator authenticator) {
        // Setup and start the first proxy
        // Generate the Kerberos token

        this.authenticator = authenticator;
        this.firstProxy = DefaultHttpProxyServer.bootstrap()
                .withAddress(localProxySocket)
                .withChainProxyManager((httpRequest, chainedProxies) -> {
                    chainedProxies.add(new MyChainedProxy());
                })
                .withFiltersSource(
                        new RequestModifierHttpFiltersSource(this.authenticator, this.requireLocalAuth,
                                this.localAuthValue))
                .start();
        this.isStarted = true;
        extensionLogging.logToOutput("Local proxy listening " + localProxySocket.toString() +
                ", forwarding to upstream proxy on " + upstreamProxyHost + ":"
                + Integer.toString(upstreamProxyPortInt));

    }

    public void stop() {
        this.firstProxy.abort();
        this.isStarted = false;
        //extensionLogging.logToOutput("Local proxy stopped");
    }

    private static class RequestModifierHttpFilters extends HttpFiltersAdapter {
        private final KerberosAuthenticator authenticator;
        private final boolean useLocalAuth;
        private final String localAuthValue;

        public RequestModifierHttpFilters(HttpRequest originalRequest, ChannelHandlerContext ctx,
                KerberosAuthenticator authenticator, boolean useLocalAuth, String localAuthValue) {
            super(originalRequest, ctx);
            this.authenticator = authenticator;
            this.useLocalAuth = useLocalAuth;
            this.localAuthValue = localAuthValue;
        }

        @Override
        public HttpResponse proxyToServerRequest(HttpObject httpObject) {
            // Here you can modify the request
            if (httpObject instanceof HttpRequest) {
                HttpRequest request = (HttpRequest) httpObject;
                HttpHeaders headers = request.headers();

                headers.set("Proxy-Authorization", "Negotiate " + authenticator.getNewToken());

            }
            return null; // returning null means continue processing
        }

        @Override
        public HttpResponse clientToProxyRequest(HttpObject httpObject) {
            if (httpObject instanceof HttpRequest) {
                HttpRequest request = (HttpRequest) httpObject;
                HttpHeaders headers = request.headers();
                if (this.useLocalAuth) {
                    if (headers.contains("Proxy-Authorization")) {
                        if (new String(Base64.getDecoder().decode(headers.get("Proxy-Authorization").split(" ")[1])).split(":")[1]
                                .equals(this.localAuthValue)) {
                            headers.remove("Proxy-Authorization");
                            return null; // returning null means continue processing
                        }
                    }
                    HttpResponse response = new DefaultHttpResponse(request.protocolVersion(),
                            new HttpResponseStatus(407,
                                    "Local Proxy Basic Authentication Required; Set it within Burp's 'Upstream Proxy' settings"));
                    response.headers().set("Connection", "close");
                    return response;
                }
            }
            return null; // returning null means continue processing
        }

    }

    private static class RequestModifierHttpFiltersSource extends HttpFiltersSourceAdapter {
        private final KerberosAuthenticator authenticator;
        private final boolean useLocalAuth;
        private final String localAuthValue;

        public RequestModifierHttpFiltersSource(KerberosAuthenticator authenticator, boolean useLocalAuth,
                String localAuthValue) {
            this.authenticator = authenticator;
            this.useLocalAuth = useLocalAuth;
            this.localAuthValue = localAuthValue;
        }

        @Override
        public HttpFilters filterRequest(HttpRequest originalRequest, ChannelHandlerContext ctx) {
            return new RequestModifierHttpFilters(originalRequest, ctx, this.authenticator, this.useLocalAuth,
                    this.localAuthValue);
        }

        @Override
        public int getMaximumRequestBufferSizeInBytes() {
            // Increase if you need to inspect large requests
            return 1024 * 1024 * 1024; // 1 GB
        }

        @Override
        public int getMaximumResponseBufferSizeInBytes() {
            // Increase if you need to inspect large responses
            return 1024 * 1024 * 1024; // 1 GB
        }
    }

}
