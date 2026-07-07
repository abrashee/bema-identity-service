package com.identity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthRateLimitFilterTest {

    @Test
    void blocksRepeatedAuthRequestsWithinTheLimitWindow() throws Exception {
        AuthRateLimitFilter filter = new AuthRateLimitFilter(new ObjectMapper(), 1, 60_000);

        MockHttpServletRequest firstRequest = new MockHttpServletRequest("POST", "/api/auth/login");
        firstRequest.addHeader("X-Forwarded-For", "203.0.113.10");
        MockHttpServletResponse firstResponse = new MockHttpServletResponse();

        filter.doFilter(firstRequest, firstResponse, new MockFilterChain());
        assertEquals(200, firstResponse.getStatus());

        MockHttpServletRequest secondRequest = new MockHttpServletRequest("POST", "/api/auth/login");
        secondRequest.addHeader("X-Forwarded-For", "203.0.113.10");
        MockHttpServletResponse secondResponse = new MockHttpServletResponse();

        filter.doFilter(secondRequest, secondResponse, new MockFilterChain());
        assertEquals(429, secondResponse.getStatus());
    }
}
