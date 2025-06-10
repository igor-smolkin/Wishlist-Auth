package org.ataraxii.authwishlist.security.dto.register;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RegisterRequestDto {
    private String username;
    private String password;
}
