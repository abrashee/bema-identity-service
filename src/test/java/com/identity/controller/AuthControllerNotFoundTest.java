package com.identity.controller;

import com.identity.audit.SecurityAuditLogger;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.identity.config.SecurityConfig;
import com.identity.jwt.JwtService;
import com.identity.security.AccessTokenRevocationService;
import com.identity.service.AuthLoginService;
import com.identity.service.AuthRegistrationService;
import com.identity.service.RefreshTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(AuthController.class)
@Import(SecurityConfig.class)
class AuthControllerNotFoundTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthLoginService authLoginService;

    @MockBean
    private AuthRegistrationService authRegistrationService;

    @MockBean
    private RefreshTokenService refreshTokenService;

    @MockBean
    private JwtService jwtService;

    @MockBean
    private AccessTokenRevocationService accessTokenRevocationService;

    @MockBean
    private SecurityAuditLogger auditLogger;

    @Test
    void unsupportedAuthenticationMethodReturnsMethodNotAllowed()
            throws Exception {
        mockMvc.perform(put("/api/auth/login"))
                .andExpect(status().isMethodNotAllowed());
    }

    @Test
    void unknownAuthenticationRouteReturnsNotFound() throws Exception {
        mockMvc.perform(get("/api/auth/does-not-exist"))
                .andExpect(status().isNotFound());
    }
}
