package org.ataraxii.authwishlist.security.dto.token;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RefreshRequestDto {
    private String refreshToken;
}
