package org.ataraxii.authwishlist.security.dto.token;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class RefreshResponseDto {
    private String accessToken;
    private String refreshToken;
}
