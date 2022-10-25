package com.example.googleoauth.config;

import com.example.googleoauth.auth.HttpCookieOAuth2AuthorizationRequestRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 인증 시 사용할 custom user service
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private CustomOAuth2UsersService customOAuth2UsersService;

    @Autowired
    private OAuth2AuthenciationSuccessHandler oAuth2AuthenciationSuccessHandler;

    @Autowired
    private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    // spring oauth2는 기본적으로 HttpSessionOAuth2AuthorizationRequestRepository를 사용해
    // Authorization Request를 저장한다.
    @Autowired
    private HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter();
    }

    /*
     기본적으로 Spring OAuth2는 authorization request를 저장하기 위해
     HttpSessionOAuth2AuthorizationRequestRepository를 사용한다.
     하지만, stateless한 서비스이므로, 세션을 저장할 수 없다.
     따라서 request를 Base64 encode된 cookie로 저장한다.
     */
    @Bean
    public HttpCookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Authorization에서 사용할 userDetailService와 password encoder를 정의한다
    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors() // cors를 허용한다
                .and()
                .sessionManagement() // session 사용 X
               .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .csrf().disable() // csrf 사용 X
                .formLogin().disable()
                .httpBasic().disable()
                // 사용자가 authenticated되지 않고 protected resource에 접근하는 경우에 invoke되는 entry point를 정의
                .exceptionHandling().authenticationEntryPoint(new RestAuthenticationEntryPoint())

                .and()
                .authorizeRequests()
                .antMatchers(
                        "/",
                        "/error",
                        "/favicon.ico",
                        "/**/*.png",
                        "/**/*.gif",
                        "/**/*.svg",
                        "/**/*.jpg",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js"
                ).permitAll() // 위의 resource는 모든 사용자에게 접근을 허용한다
                .antMatchers(
                        "/auth/**",
                        "/oauth2/**"
                ).permitAll().anyRequest().authenticated() // 인증된 사용자에게만 접근을 허용한다

                .and()
                .oauth2Login()
                .authorizationEndpoint() // oauth 로그인 시 접근할 end point를 정의한다
                /* react client 에서는 이렇게 접근하면 된다
                 # server base uri
                 API_BASE_URL = 'http://localhost:8080';

                 # oauth2 redirect uri
                 OAUTH2_REDIRECT_URI = 'http://localhost:3000/oauth2/redirect'

                 # google login uri
                 GOOGLE_AUTH_URL = API_BASE_URL + '/oauth2/authorize/google?redirect_uri=' + OAUTH2_REDIRECT_URI;
                 */
                .baseUri("/oauth2/authorize")
                .authorizationRequestRepository(cookieAuthorizationRequestRepository())

                .and()
                .userInfoEndpoint() // 로그인 시 사용할 User Service 정의
                .userService(customOAuth2UsersService)

                .and()
                .successHandler(oAuth2AuthenciationSuccessHandler) // 로그인 성공 시 invoke할 Handler 정의
                .failureHandler(oAuth2AuthenticationFailureHandler); // 로그인 실패 시 invoke할 Handler 정의

        // request 요청이 올 때마다 UsernamePasswordAuthenticationFilter 이전에 tokenAuthenticationFilter를 수행하도록 정의한다
        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
