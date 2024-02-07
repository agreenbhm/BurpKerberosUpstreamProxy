package com.agreenbhm.kerberosupstreamextension;

import org.littleshoot.proxy.*;
import org.littleshoot.proxy.impl.DefaultHttpProxyServer;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpObject;

import java.net.InetSocketAddress;

import javax.net.ssl.SSLEngine;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpHeaders;

public class ProxyChain {

    private KerberosAuthenticator authenticator;
    private HttpProxyServer firstProxy;
    int upstreamProxyPortInt;
    int localProxyPortInt;
    String upstreamProxyHost;
    boolean isStarted = false;

    private class MyChainedProxy implements ChainedProxy {
        @Override
        public InetSocketAddress getChainedProxyAddress() {
            // Address of the external proxy
            return new InetSocketAddress("127.0.0.1", upstreamProxyPortInt);
        }

        public void onCommunicationError(Throwable t) {
            // Handle communication errors here
        }

        @Override
        public SSLEngine newSslEngine() {
            // Optional: Implement if SSL support is needed
            throw new UnsupportedOperationException("SSL engine not implemented");
        }

        @Override
        public SSLEngine newSslEngine(String peerHost, int peerPort) {
            // Optional: Implement if SSL support is needed for specific host and port
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
            // Optional: Implement to handle successful connection events
        }

        @Override
        public void connectionFailed(Throwable cause) {
            // Optional: Implement to handle connection failure events
        }

        @Override
        public void disconnected() {
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
                .withPort(localProxyPortInt) // Port for the first proxy
                .withChainProxyManager((httpRequest, chainedProxies) -> {
                    chainedProxies.add(new MyChainedProxy());
                })
                .withFiltersSource(new RequestModifierHttpFiltersSource(this.authenticator))
                .start();
        this.isStarted = true;
        System.out.println("Local proxy listening 127.0.0.1:" + Integer.toString(localProxyPortInt) +
             ", forwarding to upstream proxy on " + upstreamProxyHost + ":" + Integer.toString(upstreamProxyPortInt));

    }

    public void stop() {
        this.firstProxy.abort();
        this.isStarted = false;
    }

    private static class RequestModifierHttpFilters extends HttpFiltersAdapter {
        private final KerberosAuthenticator authenticator; // Add a field to store the token

        public RequestModifierHttpFilters(HttpRequest originalRequest, ChannelHandlerContext ctx,
                KerberosAuthenticator authenticator) {
            super(originalRequest, ctx);
            this.authenticator = authenticator;
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

    }

    private static class RequestModifierHttpFiltersSource extends HttpFiltersSourceAdapter {
        private final KerberosAuthenticator authenticator; // Add a field to store the token

        public RequestModifierHttpFiltersSource(KerberosAuthenticator authenticator) {
            this.authenticator = authenticator; // Initialize the token
        }

        @Override
        public HttpFilters filterRequest(HttpRequest originalRequest, ChannelHandlerContext ctx) {
            return new RequestModifierHttpFilters(originalRequest, ctx, this.authenticator);
        }

        @Override
        public int getMaximumRequestBufferSizeInBytes() {
            // Increase if you need to inspect large requests
            return 10 * 1024 * 1024; // 10 MB
        }

        @Override
        public int getMaximumResponseBufferSizeInBytes() {
            // Increase if you need to inspect large responses
            return 10 * 1024 * 1024; // 10 MB
        }
    }

}
