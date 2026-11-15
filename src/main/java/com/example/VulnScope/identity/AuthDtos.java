package com.example.VulnScope.identity;

import java.time.Instant;
import java.util.UUID;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public final class AuthDtos {
    private AuthDtos() { }
    public record RegisterRequest(@NotBlank @Email @Size(max=320) String email, @NotBlank @Size(min=12, max=128) String password, @NotBlank @Size(min=2, max=120) String displayName) { }
    public record LoginRequest(@NotBlank @Email @Size(max=320) String email, @NotBlank @Size(max=128) String password, @Size(min=6, max=6) String mfaCode) { }
    public record PasswordResetRequest(@NotBlank @Email @Size(max=320) String email) { }
    public record PasswordResetConfirmRequest(@NotBlank @Size(min=32, max=128) String token, @NotBlank @Size(min=12, max=128) String newPassword) { }
    public record MfaCodeRequest(@NotBlank @Size(min=6, max=6) String code) { }
    public record UserResponse(UUID id, String email, String displayName) { }
    public record OrganizationResponse(UUID id, String name, Role role) { }
    public record SessionResponse(UserResponse user, OrganizationResponse organization, Instant expiresAt) { }
    public record PasswordResetResponse(String message) { }
    public record MfaEnrollmentResponse(String secret, String issuer, String account) { }
}
