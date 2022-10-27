package com.example.googleoauth.security.oauth2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 사용자가 인증이 필요한 요소에 인증 없이 접근하려 할때 호출된다.
 * 그 경우, Unauthorized(401) response를 보낸다.
 */
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private static final Logger logger = LoggerFactory.getLogger(RestAuthenticationEntryPoint.class);

    @Override
    public void commence(
            HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse,
            AuthenticationException e
    ) throws IOException, ServletException {
        logger.error("Responding with unauthorized error. Message : {}", e.getMessage());

        httpServletResponse.sendError(
                HttpServletResponse.SC_UNAUTHORIZED,
                e.getLocalizedMessage()
        );
    }
}
