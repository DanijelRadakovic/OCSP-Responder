package megatravel.com.ocsp.domain.enums;

public enum RevokeReason {
    UNSPECIFIED(0),
    KEY_COMPROMISE(1),
    CA_COMPROMISE(2),
    AFFILIATION_CHANGED(3),
    SUPERSEDED(4),
    CESSATION_OF_OPERATION(5),
    CERTIFICATE_HOLD(6),
    //UNUSED(7), deprecated
    //REMOVE_FROM_CRL(8), used only in DeltaCRLs
    PRIVILEGE_WITHDRAWN(9),
    AA_COMPROMISE(10);

    private final int code;

    RevokeReason(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}
