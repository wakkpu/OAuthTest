package com.example.googleoauth.auth;

import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** authorization request를 cookie에 save 및 retrieve하기 위해 사용됨
 *
 * OAuth2 프로토콜은 csrf 공격을 방지하기 위해 state parameter를 사용하도록 권장한다
 * 인증이 진행될 때, application이 authorization request에 state parameter를 전달하면
 * OAUth2 provider는 이 parameter를 그대로 다시 OAuth2 callback을 통해 전달한다.
 *
 * 이때 application은 initially sent된 state parameter와 OAuth2 provider가 callback에
 * 전달한 state parameter를 비교해 사이트의 위/변조를 확인한다. 만약 이 state가 일치하지 않으면
 * authentication request를 거절한다.
 *
 * application -> (state parameter) -> OAuth2 provider -> (state parameter (callback)) -> Cookie (state/redirect_uri)
 *
 * 위와 같은 process를 수행하기 위해 state 변수를 어딘가 저장할 필요가 있는데,
 * 이를 위해 short-lived cookie에 state와 redirect_uri 정보를 저장한다.
 */
@Component
public class HttpCookieOAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";

    public static final String REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri";

    private static final int cookieExpireSeconds = 180;


    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return CookieUtils.getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
                .map(cookie -> CookieUtils.deserialize(cookie, OAuth2AuthorizationRequest.class))
                .orElse(null);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        if(authorizationRequest == null) {
            CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
            CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
            return;
        }

        CookieUtils.addCookie(response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, CookieUtils.serialize(authorizationRequest), cookieExpireSeconds);

        String redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME);
        if(!redirectUriAfterLogin.equals("")) {
            CookieUtils.addCookie(response, REDIRECT_URI_PARAM_COOKIE_NAME, redirectUriAfterLogin, cookieExpireSeconds);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
        return this.loadAuthorizationRequest(request);
    }

    public void removeAuthorizationRequestCookies(HttpServletRequest request, HttpServletResponse response) {
        CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
        CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
    }
}
