# Kerberos Upstream Proxy Extension for Burp Suite

An extension to allow the use of Burp Suite with an upstream proxy that requires Kerberos authentication.

## Usage
0. Build JAR or use pre-compiled from `build/libs/*.jar`, load into Burp, then enable.
1. Configure standard Burp listener (default is 127.0.0.1:8080); it can be whatever you want, just as long as the port doesn't conflict with what we set in the extension later.
2. Go to "Kerberos Upstream Proxy" tab.
3. Configure all settings.
   * Realm should be all uppercase and is probably your domain name.
   * KDC should be a domain controller.
   * Upstream Proxy Host should be the hostname of the proxy that requires Kerberos auth.
   * Upstream Proxy Port should be the port of the proxy that requires Kerberos auth.
   * Local Proxy Port should be an unused port on 127.0.0.1 that will receive incoming requests from Burp.
   * krb5.conf Path should be the full path where you'd like to save krb5.conf (auto-populated by the extension). Note: if using Windows use forward-slashes for separation.
   * Username should be your domain username (just the username, not the domain).
   * Password should be your domain password.
4. (Optional) Click "Save Settings" button at bottom of the page to save for next time.
5. Click "Start Proxy" button at the bottom of the page.
6. In Burp Settings -> Network -> Connections, under "Upstream proxy servers", add a proxy server the following options:
   * Destination host: *
   * Proxy host: 127.0.0.1
   * Proxy port: Port number from "Local Proxy Port"
   * Authentication type: None
7. Done!  Now you can use the Burp browser (or any browser pointing to the Burp Proxy listener) with your upstream proxy that requires Kerberos.

## How it works
1. Using the settings you provide, this extension obtains a Kerberos TGT token and starts a proxy running locally.
2. When requests go into this proxy a header is added ("Proxy-Authorization: Negotiate <token>") to the request.
3. The local proxy forwards the request (with the authorization header) to your real upstream proxy.
