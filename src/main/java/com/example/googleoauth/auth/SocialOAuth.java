package com.example.googleoauth.auth;

public interface SocialOAuth {
    /**
     * 각 소셜 로그인 페이지로 리다이렉트 처리할 URL
     * 사용자로부터 로그인 요청을 받아 소셜 로그인 서버 인증용 코드를 요청
     */
    String getOAuthRedirectURL();

    /**
     * API 서버로부터 받은 코드를 활용하여 사용자 인증 정보 요청
     * @param code API 서버에서 받아온 코드
     * @return API 서버로부터 받은 JSON 형태의 결과를 문자열로 반환
     */
    String requestAccessToken(String code);
}
