package megatravel.com.ocsp.domain;

import megatravel.com.ocsp.domain.enums.CerType;
import megatravel.com.ocsp.domain.enums.RevokeReason;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
public class Certificate {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false, unique = true)
    private String serialNumber;

    @Column(unique = true)
    private String distinguishedName;

    @Column(nullable = false)
    @Enumerated(EnumType.ORDINAL)
    private CerType type;

    @Column(nullable = false)
    private boolean active;

    @Column
    @Enumerated(EnumType.ORDINAL)
    private RevokeReason revokeReason;

    @Column(nullable = false)
    private LocalDateTime expirationDate;

    @Column
    private LocalDateTime revocationDate;

    public Certificate() {
    }

    public Certificate(Long id, String serialNumber, String distinguishedName, CerType type, boolean active,
                       RevokeReason revokeReason, LocalDateTime expirationDate, LocalDateTime revocationDate) {
        this.id = id;
        this.serialNumber = serialNumber;
        this.distinguishedName = distinguishedName;
        this.type = type;
        this.active = active;
        this.revokeReason = revokeReason;
        this.expirationDate = expirationDate;
        this.revocationDate = revocationDate;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getDistinguishedName() {
        return distinguishedName;
    }

    public void setDistinguishedName(String distinguishedName) {
        this.distinguishedName = distinguishedName;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public CerType getType() {
        return type;
    }

    public void setType(CerType type) {
        this.type = type;
    }

    public RevokeReason getRevokeReason() {
        return revokeReason;
    }

    public void setRevokeReason(RevokeReason revokeReason) {
        this.revokeReason = revokeReason;
    }

    public LocalDateTime getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(LocalDateTime expirationDate) {
        this.expirationDate = expirationDate;
    }

    public LocalDateTime getRevocationDate() {
        return revocationDate;
    }

    public void setRevocationDate(LocalDateTime revocationDate) {
        this.revocationDate = revocationDate;
    }
}
