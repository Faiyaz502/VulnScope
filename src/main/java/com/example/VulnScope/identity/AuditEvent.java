package com.example.VulnScope.identity;

import java.time.Instant;
import java.util.UUID;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "audit_events")
public class AuditEvent {
    @Id private UUID id;
    @Column(name = "organization_id") private UUID organizationId;
    @Column(name = "actor_user_id") private UUID actorUserId;
    @Column(name = "event_type", nullable = false, length = 80) private String eventType;
    @Column(name = "occurred_at", nullable = false) private Instant occurredAt;
    @Column(name = "ip_address", length = 45) private String ipAddress;
    @Column(name = "metadata_json", columnDefinition = "text") private String metadataJson;
    protected AuditEvent() { }
    public AuditEvent(UUID organizationId, UUID actorUserId, String eventType, String ipAddress, String metadataJson) { this.id=UUID.randomUUID(); this.organizationId=organizationId; this.actorUserId=actorUserId; this.eventType=eventType; this.occurredAt=Instant.now(); this.ipAddress=ipAddress; this.metadataJson=metadataJson; }
}
