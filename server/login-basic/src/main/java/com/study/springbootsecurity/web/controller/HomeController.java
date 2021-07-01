package com.study.springbootsecurity.web.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class HomeController {

    @ResponseBody   //이걸 설정해줘야 JSON 객체로 전달됨
    @GetMapping("/auth")
    public Authentication auth(){
        return SecurityContextHolder.getContext().getAuthentication();  //Authentication 정보를 볼 수 있음
    }

    @GetMapping("/")
    public String main(){
        return "index";
    }

    @GetMapping("/login")
    public String login(){
        return "loginForm";
    }



    @GetMapping("/login-error")
    public String loginError(Model model){
        model.addAttribute("loginError", true);
        return "loginForm";
    }

    @GetMapping("/access-denied")
    public String accessDenied(){
        return "AccessDenied";
    }

    @PreAuthorize("hasAnyAuthority('ROLE_USER')")
    @GetMapping("/user-page")
    public String userPage(){
        return "UserPage";
    }

    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    @GetMapping("/admin-page")
    public String adminPage(){
        return "AdminPage";
    }


}

