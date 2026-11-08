package com.example.VulnScope.identity;

import java.time.Instant;
import java.util.UUID;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public final class AuthDtos {
    private AuthDtos() { }
    public record RegisterRequest(@NotBlank @Email @Size(max=320) String email, @NotBlank @Size(min=12, max=128) String password, @NotBlank @Size(min=2, max=120) String displayName) { }
    public record LoginRequest(@NotBlank @Email @Size(max=320) String email, @NotBlank @Size(max=128) String password) { }
    public record UserResponse(UUID id, String email, String displayName) { }
    public record OrganizationResponse(UUID id, String name, Role role) { }
    public record SessionResponse(UserResponse user, OrganizationResponse organization, Instant expiresAt) { }
}
