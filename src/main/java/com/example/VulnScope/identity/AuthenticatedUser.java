package com.example.VulnScope.identity;

import java.util.UUID;

public record AuthenticatedUser(UUID userId, UUID organizationId, Role role) { }
