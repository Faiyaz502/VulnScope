package com.example.VulnScope.identity;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthIntegrationTest {
    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired AuditEventRepository auditEvents;
    @Autowired AuthSessionRepository sessions;
    @Autowired MembershipRepository memberships;
    @Autowired OrganizationRepository organizations;
    @Autowired UserAccountRepository users;

    @BeforeEach
    void cleanDatabase() {
        auditEvents.deleteAll(); sessions.deleteAll(); memberships.deleteAll(); organizations.deleteAll(); users.deleteAll();
    }

    @Test
    void registrationRequiresCsrfAndCreatesSession() throws Exception {
        String body = "{\"email\":\"owner@example.com\",\"password\":\"strong-password-123\",\"displayName\":\"Owner\"}";
        mockMvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isForbidden());

        Csrf csrf = csrf();
        MvcResult result = mockMvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content(body)
                .cookie(csrf.cookie()).header("X-XSRF-TOKEN", csrf.token()))
            .andExpect(status().isOk())
            .andExpect(cookie().exists("vulnscope_session"))
            .andExpect(jsonPath("$.user.email").value("owner@example.com"))
            .andExpect(jsonPath("$.organization.role").value("OWNER"))
            .andReturn();
        if (result.getResponse().getCookie("vulnscope_session") == null) throw new AssertionError("session cookie missing");
    }

    @Test
    void invalidCredentialsDoNotRevealWhetherEmailExists() throws Exception {
        Csrf csrf = csrf();
        String body = "{\"email\":\"unknown@example.com\",\"password\":\"wrong-password\"}";
        mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content(body)
                .cookie(csrf.cookie()).header("X-XSRF-TOKEN", csrf.token()))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.errorCode").value("INVALID_CREDENTIALS"));
    }

    @Test
    void organizationCannotBeReadByAnotherUser() throws Exception {
        Csrf firstCsrf = csrf();
        String firstBody = "{\"email\":\"first@example.com\",\"password\":\"strong-password-123\",\"displayName\":\"First\"}";
        MvcResult first = mockMvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content(firstBody)
                .cookie(firstCsrf.cookie()).header("X-XSRF-TOKEN", firstCsrf.token())).andExpect(status().isOk()).andReturn();
        UUID firstOrganization = UUID.fromString(objectMapper.readTree(first.getResponse().getContentAsString()).at("/organization/id").asText());

        Csrf secondCsrf = csrf();
        String secondBody = "{\"email\":\"second@example.com\",\"password\":\"strong-password-123\",\"displayName\":\"Second\"}";
        MvcResult second = mockMvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content(secondBody)
                .cookie(secondCsrf.cookie()).header("X-XSRF-TOKEN", secondCsrf.token())).andExpect(status().isOk()).andReturn();
        String secondSession = second.getResponse().getCookie("vulnscope_session").getValue();

        mockMvc.perform(get("/api/v1/organizations/" + firstOrganization).cookie(new jakarta.servlet.http.Cookie("vulnscope_session", secondSession)))
            .andExpect(status().isForbidden());
    }

    private Csrf csrf() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/auth/csrf")).andExpect(status().isOk()).andReturn();
        MockHttpServletResponse response = result.getResponse();
        JsonNode json = objectMapper.readTree(response.getContentAsString());
        return new Csrf(json.get("token").asText(), response.getCookie("XSRF-TOKEN"));
    }

    private record Csrf(String token, jakarta.servlet.http.Cookie cookie) { }
}
