package com.example.VulnScope.identity;

import java.time.Instant;
import java.util.UUID;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "organizations")
public class Organization {
    @Id private UUID id;
    @Column(nullable = false, length = 160) private String name;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    protected Organization() { }
    public Organization(UUID id, String name) { this.id=id; this.name=name; this.createdAt=Instant.now(); }
    public UUID getId() { return id; }
    public String getName() { return name; }
}
