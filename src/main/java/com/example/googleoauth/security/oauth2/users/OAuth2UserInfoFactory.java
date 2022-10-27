package com.example.googleoauth.security.oauth2.users;

import com.example.googleoauth.exception.OAuth2AuthenticationProcessingException;
import com.example.googleoauth.model.AuthProvider;

import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
            return new GoogleOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationProcessingException(
                    "Sorry! Login with " + registrationId +" is not supported yet"
            );
        }
    }
}
