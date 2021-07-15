package com.study.springbootsecurity.web.student;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Student {
    private String id;
    private String username;
    private Set<GrantedAuthority>  role;    //이게 도메인의 principal이 됨

}
