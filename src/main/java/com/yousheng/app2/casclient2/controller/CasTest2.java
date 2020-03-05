package com.yousheng.app2.casclient2.controller;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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
    public String test1(String ticket, HttpSession session, HttpServletRequest request) throws IOException {
        log.info("进入登录请求..........");
        //cas单点登录的用户名就是：_cas_stateful_ ，用户凭证是server传回来的ticket
        String username = CasAuthenticationFilter.CAS_STATEFUL_IDENTIFIER;
        UsernamePasswordAuthenticationToken token=new UsernamePasswordAuthenticationToken(username,request.getRemoteUser());
        Authentication authentication=authenticationManager.authenticate(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
        log.info("登录成功..........");
        return request.getRemoteUser();
    }

    @RequestMapping("/logout2/success2")
    public String logoutsuccess(HttpSession session) {
        return "logoutsuccess2";
    }
}
