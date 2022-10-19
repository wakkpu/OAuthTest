package com.example.googleoauth.service;

import com.example.googleoauth.auth.GoogleOAuth;
import com.example.googleoauth.entity.enums.SocialLoginType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletResponse;

@Service
@RequiredArgsConstructor
public class OAuthService {
    private final GoogleOAuth googleOAuth;

    private final HttpServletResponse response;

    public void requestAuth(SocialLoginType socialLoginType) {
        String redirectURL;
        switch (socialLoginType) {
            case google:
                redirectURL = googleOAuth.getOAuthRedirectURL();
                break;
            default:
                throw new IllegalArgumentException("지원하지 않는 소셜 로그인입니다");
        }

        try {
            response.sendRedirect(redirectURL);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
