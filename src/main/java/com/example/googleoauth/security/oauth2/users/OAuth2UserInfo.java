package com.example.googleoauth.security.oauth2.users;

import java.util.Map;

/**
 * OAuth provider별로 다른 JSON 형태의 response를 보내준다.
 * Spring Security는 이 response를 Key-Value의 Map 형태로 파싱한다.
 */
public abstract class OAuth2UserInfo {
    protected Map<String, Object> attributes;

    public OAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public abstract String getId();

    public abstract String getName();

    public abstract String getEmail();
}
