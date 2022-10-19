package com.example.googleoauth.controller;

import com.example.googleoauth.entity.enums.SocialLoginType;
import com.example.googleoauth.service.OAuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin
@RequiredArgsConstructor
@RequestMapping("/auth")
@Slf4j
public class OAuthController {
    private final OAuthService oAuthService;

    /**
     * 사용자로부터 Social Login Type을 입력 받아 SNS 로그인 요청을 처리
     * @param socialLoginType enum(google, kakao, naver, facebook)
     */
    @GetMapping("/{socialLoginType}")
    public void socialLoginType(
            @PathVariable(name = "socialLoginType")
            SocialLoginType socialLoginType
    ) {
        log.info("사용자로부터 소셜 로그인 요청이 들어옴 :: {} Social Login", socialLoginType);

        oAuthService.requestAuth(socialLoginType);
    }

    /**
     * 소셜 로그인 API 서버 요청에 의한 콜백 처리
     * @param socialLoginType enum(google, kakao, naver, facebook)
     * @param code API 서버로부터 넘어오는 code
     * @return 소셜 로그인 결과로 받은 JSON 형태의 문자열
     */
    @GetMapping("/{socialLoginType}/callback")
    public String callback(
            @PathVariable(name = "socialLoginType")
            SocialLoginType socialLoginType,
            @RequestParam(name = "code")
            String code
    ) {
        log.info("소셜 로그인 API 서버로부터 받은 code :: {}", code);
        return "";
    }
}
