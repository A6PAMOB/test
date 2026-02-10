package com.example.files;

import com.sun.security.auth.module.Krb5LoginModule;
import jcifs.CIFSContext;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.smb.*;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class TestTfs {

    public static final String KERBEROS_LOGIN = "KerberosLogin";

    public static void main(String[] args) {
        System.setProperty("java.security.krb5.kdc", "kerberos.tfs.local");
        System.setProperty("java.security.krb5.realm", "TFS.LOCAL");

        String server = "smb://files.tfs.local/tfs";
        String principalName = "tfsclient@TFS.LOCAL";
        String password = "tfs";

        try {
            Subject subject = getSubject(principalName, password);
            Kerb5Authenticator kerb5Authenticator = new Kerb5Authenticator(subject);

            Properties props = new Properties();
            props.setProperty("jcifs.smb.client.minVersion", "SMB202");
            props.setProperty("jcifs.smb.client.maxVersion", "SMB311");

            CIFSContext baseContext = new BaseContext(new PropertyConfiguration(props));

            CIFSContext kerbContext = baseContext.withCredentials(kerb5Authenticator);

            try (SmbFile smbFile = new SmbFile(server, kerbContext)) {
                SmbFile[] files = smbFile.listFiles();

                for(SmbFile file : files){
                    if(file.isDirectory()) {
                        System.out.println("[DIR]: " + file.getName());
                    } else {
                        System.out.println("[FILE]: " + file.getName() + ", размер: " + file.length() + " байт");
                    }
                }

            }

        } catch(Exception ex) {
            System.err.println("Общая ошибка: " + ex.getMessage());
        }
    }

    public static Subject getSubject(String principalName, String password) {
        Map<String, String> options = new HashMap<>();
        options.put("client", "TRUE");
        options.put("useTicketCache", "false");
        options.put("doNotPrompt", "false");
        options.put("principal", principalName);

        AppConfigurationEntry[] entries = new AppConfigurationEntry[] {
                new AppConfigurationEntry(
                        Krb5LoginModule.class.getName(),
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                        options
                )
        };

        Configuration programmaticConfig = new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                    if (KERBEROS_LOGIN.equals(name)) {
                    return entries;
                }
                return null;
            }
        };

        try {
            Configuration.setConfiguration(programmaticConfig);

            LoginContext lc = getLoginContext(principalName, password);
            System.out.println("Authentication Succeeded!");
            return lc.getSubject();
        } catch (LoginException e) {
            System.err.println("Authentication Failed: " + e.getMessage());
            e.printStackTrace();
        }

        return null;
    }

    private static LoginContext getLoginContext(String principalName, String password) throws LoginException {
        LoginContext lc = new LoginContext(KERBEROS_LOGIN, callbacks -> {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    ((NameCallback) callback).setName(principalName);
                } else if (callback instanceof PasswordCallback) {
                    ((PasswordCallback) callback).setPassword(password.toCharArray());
                } else {
                    throw new UnsupportedCallbackException(callback, "Unsupported Callback Type");
                }
            }
        });

        lc.login();
        return lc;
    }

}
