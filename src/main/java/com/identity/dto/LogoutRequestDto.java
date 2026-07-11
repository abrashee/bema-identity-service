package com.identity.dto;

import jakarta.validation.constraints.NotBlank;

public record LogoutRequestDto(
        @NotBlank String refreshToken,
        @NotBlank String accessToken
) {}
