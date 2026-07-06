package com.identity.dto;

public record UserResponseDto(
        String id,
        String email,
        String name
) {}