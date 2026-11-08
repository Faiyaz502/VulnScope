package com.example.VulnScope.identity;

import java.time.Instant;
import java.util.UUID;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "users")
public class UserAccount {
    @Id private UUID id;
    @Column(nullable = false, unique = true, length = 320) private String email;
    @Column(name = "password_hash", nullable = false, length = 255) private String passwordHash;
    @Column(name = "display_name", nullable = false, length = 120) private String displayName;
    @Column(nullable = false) private boolean enabled;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    protected UserAccount() { }
    public UserAccount(UUID id, String email, String passwordHash, String displayName) { this.id=id; this.email=email; this.passwordHash=passwordHash; this.displayName=displayName; this.enabled=true; this.createdAt=Instant.now(); }
    public UUID getId() { return id; }
    public String getEmail() { return email; }
    public String getPasswordHash() { return passwordHash; }
    public String getDisplayName() { return displayName; }
    public boolean isEnabled() { return enabled; }
}
