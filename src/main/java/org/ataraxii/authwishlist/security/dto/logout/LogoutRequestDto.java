package org.ataraxii.authwishlist.security.dto.logout;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LogoutRequestDto {
    private String accessToken;
}
