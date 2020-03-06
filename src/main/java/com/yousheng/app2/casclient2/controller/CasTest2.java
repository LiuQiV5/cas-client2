package com.yousheng.app2.casclient2.controller;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;


/**
 * @author ：lq
 * @date ：2020/2/27
 * @time：22:47
 */
@RestController
@Slf4j
@AllArgsConstructor
public class CasTest2 {

    private final AuthenticationManager authenticationManager;


    @RequestMapping("/api/user/info")
    public UserDetails test1(String ticket, HttpSession session, HttpServletRequest request) throws IOException {
        log.info("进入登录请求..........");
        CasAuthenticationToken casAuthenticationToken = null;
        //cas单点登录的用户名就是：_cas_stateful_ ，用户凭证是server传回来的ticket
        String username = CasAuthenticationFilter.CAS_STATEFUL_IDENTIFIER;
        UsernamePasswordAuthenticationToken token=new UsernamePasswordAuthenticationToken(username,ticket);
        Authentication authentication=authenticationManager.authenticate(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
        log.info("登录成功..........");
        if (authentication instanceof CasAuthenticationToken) {
            casAuthenticationToken = (CasAuthenticationToken) authentication;
        }
        return ObjectUtils.isEmpty(casAuthenticationToken)?null:casAuthenticationToken.getUserDetails();
    }

    /**
     * 必须要有ADMIN权限的才能访问
     */
    @PreAuthorize("hasAuthority('AUTH_0')")
    @RequestMapping("/authorize")
    public String authorize() {
        return "index222";
    }

    @RequestMapping("/hello")
    public String hello() {
        return "不验证哦";
    }

    /**
     * 有TEST权限的才能访问
     */
    @PreAuthorize("hasAuthority('AUTH_1')")
    @RequestMapping("/security")
    public String security() {
        return "hello world security";
    }
}
