package org.sid.authservice.sec.security;

public class SecurityConstants {
    // cette classe permet de configurer le token
    public static final long EXPIRATION_TIME_ACCESS_TOKEN = 1*60000;// 1 minute
    public static final long EXPIRATION_TIME_REFRSH_TOKEN = 10*24*60*60000; // 10 Days
    // le token sera préfixé avec le prefix Bearer +TOKEN
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
    public static final String SIGN_UP_URL = "/users";
    public static final String TOKEN_SECRET = "dfg523hdc612zwerop3tghg1ddfdfgdsdfeqaas?=-0ljznm0-9";
}
