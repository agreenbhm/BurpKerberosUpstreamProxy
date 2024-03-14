package com.agreenbhm.kerberosupstreamextension;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class CreateKrb5Conf {

    public CreateKrb5Conf(String krb5ConfPath, ExtensionLogging extensionLogging) {
        File krb5ConfFile = new File(krb5ConfPath);

        // Check if the krb5.conf file exists
        if (!krb5ConfFile.exists()) {
            try {
                // Ensure parent directories exist
                krb5ConfFile.getParentFile().mkdirs();

                // Create the file and write the Kerberos configuration
                try (FileWriter writer = new FileWriter(krb5ConfFile)) {
                    writer.write("[libdefaults]\nforwardable = true\n");
                    extensionLogging.logToOutput("krb5.conf file created successfully.");
                }
            } catch (IOException e) {
                extensionLogging.logToError("Failed to create krb5.conf file: " + e.getMessage());
            }
        } else {
            extensionLogging.logToOutput("krb5.conf file already exists.");
        }
    }
}
