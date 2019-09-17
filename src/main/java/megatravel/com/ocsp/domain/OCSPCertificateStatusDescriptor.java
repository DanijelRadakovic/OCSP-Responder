package megatravel.com.ocsp.domain;

import org.bouncycastle.cert.ocsp.CertificateStatus;

import java.time.LocalDateTime;

/**
 * Holds information about certificate status, when this status was determined and
 * when the next update will happen.
 */
public class OCSPCertificateStatusDescriptor {

    private CertificateStatus certificateStatus;
    private LocalDateTime currentUpdate;
    private LocalDateTime nextUpdate;

    public OCSPCertificateStatusDescriptor() {
    }

    public OCSPCertificateStatusDescriptor(CertificateStatus certificateStatus, LocalDateTime currentUpdate,
                                           LocalDateTime nextUpdate) {
        this.certificateStatus = certificateStatus;
        this.currentUpdate = currentUpdate;
        this.nextUpdate = nextUpdate;
    }

    public CertificateStatus getCertificateStatus() {
        return certificateStatus;
    }

    public void setCertificateStatus(CertificateStatus certificateStatus) {
        this.certificateStatus = certificateStatus;
    }

    public LocalDateTime getCurrentUpdate() {
        return currentUpdate;
    }

    public void setCurrentUpdate(LocalDateTime currentUpdate) {
        this.currentUpdate = currentUpdate;
    }

    public LocalDateTime getNextUpdate() {
        return nextUpdate;
    }

    public void setNextUpdate(LocalDateTime nextUpdate) {
        this.nextUpdate = nextUpdate;
    }
}
