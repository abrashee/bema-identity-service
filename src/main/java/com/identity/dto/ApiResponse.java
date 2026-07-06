package com.identity.dto;

public record ApiResponse<T>(
        String message,
        T data
) {}