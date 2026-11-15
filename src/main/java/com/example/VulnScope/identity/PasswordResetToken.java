package com.example.VulnScope.identity;

import java.time.Instant;
import java.util.UUID;
import jakarta.persistence.*;

@Entity
@Table(name = "password_reset_tokens")
public class PasswordResetToken {
    @Id private UUID id;
    @Column(name = "user_id", nullable = false) private UUID userId;
    @Column(name = "token_hash", nullable = false, unique = true, length = 64) private String tokenHash;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Column(name = "used_at") private Instant usedAt;
    protected PasswordResetToken() { }
    public PasswordResetToken(UUID id, UUID userId, String tokenHash, Instant expiresAt) { this.id=id; this.userId=userId; this.tokenHash=tokenHash; this.expiresAt=expiresAt; }
    public UUID getUserId() { return userId; }
    public boolean isUsable(Instant now) { return usedAt == null && expiresAt.isAfter(now); }
    public void markUsed() { usedAt = Instant.now(); }
}
