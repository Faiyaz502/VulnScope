package com.example.VulnScope.identity;

import java.util.List;
import java.util.UUID;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PathVariable;

@RestController
@RequestMapping("/api/v1/organizations")
public class OrganizationController {
    private final AuthService authService;
    public OrganizationController(AuthService authService) { this.authService = authService; }

    @GetMapping
    public List<AuthDtos.OrganizationResponse> list(@AuthenticationPrincipal AuthenticatedUser principal) {
        return authService.organizationsFor(principal);
    }

    @GetMapping("/{organizationId}")
    public AuthDtos.OrganizationResponse get(@PathVariable UUID organizationId, @AuthenticationPrincipal AuthenticatedUser principal) {
        return authService.organizationFor(principal, organizationId);
    }
}
