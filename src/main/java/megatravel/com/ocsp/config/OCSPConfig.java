package megatravel.com.ocsp.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OCSPConfig {

    @Value("${ocsp.keystore.path}")
    private String keystore;

    @Value("${ocsp.keystore.password}")
    private String keystorePassword;

    @Value("${ocsp.keystore.alias}")
    private String keystoreAlias;

    @Value("${ocsp.provider}")
    private String provider;

    @Value("${ocsp.reject-unknown}")
    private boolean rejectUnknown;

    @Value("${ocsp.refresh-seconds}")
    private int refreshRate;

    public String getKeystore() {
        return keystore;
    }

    public void setKeystore(String keystore) {
        this.keystore = keystore;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public void setKeystorePassword(String keystorePassword) {
        this.keystorePassword = keystorePassword;
    }

    public String getKeystoreAlias() {
        return keystoreAlias;
    }

    public void setKeystoreAlias(String keystoreAlias) {
        this.keystoreAlias = keystoreAlias;
    }

    public boolean isRejectUnknown() {
        return rejectUnknown;
    }

    public void setRejectUnknown(boolean rejectUnknown) {
        this.rejectUnknown = rejectUnknown;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public int getRefreshRate() {
        return refreshRate;
    }

    public void setRefreshRate(int refreshRate) {
        this.refreshRate = refreshRate;
    }
}
