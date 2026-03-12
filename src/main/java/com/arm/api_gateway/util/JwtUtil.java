package com.arm.api_gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;

public class JwtUtil {

    private static final String SECRET =
            "mysecretkeymysecretkeymysecretkey12";

    private static SecretKey getKey() {
        return Keys.hmacShaKeyFor(SECRET.getBytes());
    }

    public static Claims validateToken(String token) {

        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
