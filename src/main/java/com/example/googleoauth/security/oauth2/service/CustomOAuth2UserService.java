package com.example.googleoauth.security.oauth2.service;

import com.example.googleoauth.exception.OAuth2AuthenticationProcessingException;
import com.example.googleoauth.model.AuthProvider;
import com.example.googleoauth.model.User;
import com.example.googleoauth.repository.UserRepository;
import com.example.googleoauth.security.oauth2.UserPrincipal;
import com.example.googleoauth.security.oauth2.users.OAuth2UserInfo;
import com.example.googleoauth.security.oauth2.users.OAuth2UserInfoFactory;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Spring Security의 DefaultOAuth2UserService를 확장하고, loadUser 메서드를 구현
 */
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    // OAuth Provider로부터 access token을 획득한 뒤 호출된다
    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        // OAuth Provider로부터 user detail을 획득한다
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        try { // 유저 정보가 DB에 있는지, 없는지 확인 후 저장 혹은 수정
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    // 획득한 정보가 DB에 있는지, 없는지에 따라 정보를 갱신하거나 저장합니다
    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo =
                OAuth2UserInfoFactory.getOAuth2UserInfo(
                        oAuth2UserRequest.getClientRegistration().getRegistrationId(),
                        oAuth2User.getAttributes()
                );

        if(StringUtils.isBlank(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(oAuth2UserInfo.getEmail());

        User user;
        if(userOptional.isPresent()) {
            user = userOptional.get();

            if(!user.getProvider().equals(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()))) {
                throw new OAuth2AuthenticationProcessingException(
                        "Looks like you're signed up with " + user.getProvider() +
                                " account. Please use your " + user.getProvider() + " account to login"
                        );
            }
            user = updateExistingUser(user, oAuth2UserInfo);

        } else {
            user = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
        }
        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    // 신규 user일 경우 DB에 등록합니다
    private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
        User user = User.builder()
                .provider(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()))
                .providerId(oAuth2UserInfo.getId())
                .name(oAuth2UserInfo.getName())
                .email(oAuth2UserInfo.getEmail())
                .build();

        return userRepository.save(user);
    }

    // 만약 획득한 user 정보가 이미 DB에 있는 경우, 해당 user 정보를 update합니다
    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {
        existingUser.setName(oAuth2UserInfo.getName());

        return userRepository.save(existingUser);
    }
}
