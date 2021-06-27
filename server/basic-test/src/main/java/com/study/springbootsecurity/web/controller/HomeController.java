package com.study.springbootsecurity.web.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @RequestMapping("/")
    public String index(){
        return "홈페이지";
    }

    /**
     * 사용자가 어떤 인증과 권한으로 접속했는지 알 수 있는 컨트롤러
     */
    @RequestMapping("/auth")
    public Authentication auth(){
        return SecurityContextHolder.getContext().getAuthentication();
    }


    /**
     * 개인정보를 보여주는 컨트롤러
     */
    @PreAuthorize("hasAnyAuthority('ROLE_USER')") //이 URL에 접근하는 사람의 권한을 체크함, 권한별로 접근을 통제하게 됨
                                                  // (반드시 SecurityConfig의 @EnableGlobalMethodSecurity의 옵션(@PreAuthorize라면 prePostEnabled = true, @Secured라면 SecuredEnable = true)을 설정해줘야 통제가능)
    @RequestMapping("/user")
    public SecurityMessage user(){
        return SecurityMessage.builder().auth(SecurityContextHolder.getContext().getAuthentication())
                .message("User 정보").build();

    }
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    @RequestMapping("/admin")
    public SecurityMessage admin(){
        return SecurityMessage.builder().auth(SecurityContextHolder.getContext().getAuthentication())
                .message("관리자 정보").build();
    }
}
