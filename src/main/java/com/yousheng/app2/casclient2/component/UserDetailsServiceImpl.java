package com.yousheng.app2.casclient2.component;

import com.yousheng.app2.casclient2.entity.UserAccount;
import com.yousheng.app2.casclient2.service.UserAccountService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

/**
 * @author:lq
 * @date: 2020/3/5
 * @time: 16:47
 */
@Component
@AllArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService,AuthenticationUserDetailsService<CasAssertionAuthenticationToken> {

    private final UserAccountService userAccountService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userAccountService.findByUsername(username);
    }

    /**
     * @param token The pre-authenticated authentication token
     * @return UserDetails for the given authentication token, never null.
     * @throws UsernameNotFoundException if no user details can be found for the given
     *                                   authentication token
     */
    @Override
    public UserDetails loadUserDetails(CasAssertionAuthenticationToken token) throws UsernameNotFoundException {
        String name = token.getName();
        log.info("获得的用户名："+name);
        UserAccount user = userAccountService.findByUsername(name);
        if (user==null){
            throw new UsernameNotFoundException(name+"不存在");
        }
        return user;
    }
}
