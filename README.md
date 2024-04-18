# Kerberos Upstream Proxy Extension for Burp Suite

An extension to allow the use of Burp Suite with an upstream proxy that requires Kerberos authentication.

## Usage - As Burp Extension
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
   * (Optional) Require Local Auth should be enabled if you wish to require authentication to use the proxy you're hosting locally.
   * (Optional) Local Auth Value should be set to a string of your choosing which will be used as the local authentication password, if enabled.
4. (Optional) Click "Save Settings" button at bottom of the page to save for next time.
5. Click "Start Proxy" button at the bottom of the page.
6. In Burp Settings -> Network -> Connections, under "Upstream proxy servers", add a proxy server the following options:
   * Destination host: *
   * Proxy host: 127.0.0.1
   * Proxy port: Port number from "Local Proxy Port"
   * Authentication
     * If "Require Local Auth" is disabled: Type: None
     * If "Require Local Auth" is enabled: Type: Basic, Username: \<anything\>, Password: \<string from Local Auth Value\>
7. Done!  Now you can use the Burp browser (or any browser pointing to the Burp Proxy listener) with your upstream proxy that requires Kerberos.

## Usage - As Standalone Tool
0. Build JAR or use pre-compiled from `build/libs/*.jar`
1. Launch via CLI as `java -jar <jar-file>.jar -h` to show help, then re-run with necessary arguments.  "Require Local Auth" and "Local Auth Value" are optional.
2. If using local auth, ensure Proxy-Authorization is being sent with whatever tool you're using.  For curl, you'd use the `--proxy-user username:password` argument.
3. When using as a standalone tool you can specify the IP to listen on (including 0.0.0.0).  If you don't specify an IP it'll default to localhost.

## How it works
1. Using the settings you provide, this extension obtains a Kerberos TGT token and starts a proxy running locally.
2. When requests go into this proxy a header is added ("Proxy-Authorization: Negotiate <token>") to the request.
3. The local proxy forwards the request (with the authorization header) to your real upstream proxy.
