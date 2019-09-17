package megatravel.com.ocsp.domain.enums;

public enum CertificateStatus {
    VALID,
    REVOKED,
    EXPIRED,
    UNKNOWN;

    public static CertificateStatus fromString(String status) {
        switch (status.toUpperCase()) {
            case "VALID":
                return VALID;
            case "REVOKED":
                return REVOKED;
            case "EXPIRED":
                return EXPIRED;
            case "UNKNOWN":
                return UNKNOWN;
            default:
                throw new IllegalArgumentException("Did not find valid status: " + status);
        }
    }
}
