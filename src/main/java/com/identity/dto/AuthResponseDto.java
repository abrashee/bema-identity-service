package com.identity.dto;

public record AuthResponseDto(
        String token,
        String refreshToken,
        UserResponseDto user
) {}
