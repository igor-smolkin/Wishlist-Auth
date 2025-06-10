package org.ataraxii.authwishlist.security.dto.register;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RegisterResponseDto {
    private String username;
    private String message;
}
