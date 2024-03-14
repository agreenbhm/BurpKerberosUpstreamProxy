package com.agreenbhm.kerberosupstreamextension;

import burp.api.montoya.logging.Logging;

public class ExtensionLogging {
    private String type;
    private Logging logging;

    public ExtensionLogging(Logging logging) {
        this.logging = logging;
        this.type = "extension";
    }

    public ExtensionLogging(){
        this.type = "standalone";
    }

    public void logToOutput(String message){
        if (this.type.equals("extension")){
            this.logging.logToOutput(message);
        } else {
            System.out.println(message);
        }
    }

    public void logToError(String message){
        if (this.type.equals("extension")){
            this.logging.logToError(message);
        } else {
            System.err.println(message);
        }
    }
    
    
    
}
