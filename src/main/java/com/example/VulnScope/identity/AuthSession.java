package com.example.VulnScope.identity;

import java.time.Instant;
import java.util.UUID;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "auth_sessions")
public class AuthSession {
    @Id private UUID id;
    @Column(name = "user_id", nullable = false) private UUID userId;
    @Column(name = "token_hash", nullable = false, unique = true, length = 64) private String tokenHash;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Column(name = "last_seen_at", nullable = false) private Instant lastSeenAt;
    @Column(name = "revoked_at") private Instant revokedAt;
    protected AuthSession() { }
    public AuthSession(UUID id, UUID userId, String tokenHash, Instant expiresAt) { this.id=id; this.userId=userId; this.tokenHash=tokenHash; this.createdAt=Instant.now(); this.expiresAt=expiresAt; this.lastSeenAt=this.createdAt; }
    public UUID getUserId() { return userId; }
    public boolean isActive(Instant now) { return revokedAt == null && expiresAt.isAfter(now); }
    public void revoke() { revokedAt=Instant.now(); }
    public void touch() { lastSeenAt=Instant.now(); }
}
