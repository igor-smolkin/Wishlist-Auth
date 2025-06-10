package org.ataraxii.authwishlist.security.dto.login;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginRequestDto {
    private String username;
    private String password;
}
