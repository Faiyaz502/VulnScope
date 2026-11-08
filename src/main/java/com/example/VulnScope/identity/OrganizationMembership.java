package com.example.VulnScope.identity;

import java.time.Instant;
import java.util.UUID;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(name = "organization_memberships", uniqueConstraints = @UniqueConstraint(columnNames = {"organization_id", "user_id"}))
public class OrganizationMembership {
    @Id private UUID id;
    @Column(name = "organization_id", nullable = false) private UUID organizationId;
    @Column(name = "user_id", nullable = false) private UUID userId;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private Role role;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    protected OrganizationMembership() { }
    public OrganizationMembership(UUID id, UUID organizationId, UUID userId, Role role) { this.id=id; this.organizationId=organizationId; this.userId=userId; this.role=role; this.createdAt=Instant.now(); }
    public UUID getOrganizationId() { return organizationId; }
    public UUID getUserId() { return userId; }
    public Role getRole() { return role; }
}
