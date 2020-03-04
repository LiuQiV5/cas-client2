package com.yousheng.app2.casclient2.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;


/**
 * @author ：lq
 * @date ：2020/2/27
 * @time：22:47
 */
@Controller
public class CasTest2 {

    @RequestMapping("/api/user/info")
    @ResponseBody
    public String test1(HttpServletResponse response, HttpServletRequest request) throws IOException {
        System.out.println(222222);
        return request.getRemoteUser();
    }

    @RequestMapping("/logout2/success2")
    @ResponseBody
    public String logoutsuccess(HttpSession session) {
        return "logoutsuccess2";
    }
}
