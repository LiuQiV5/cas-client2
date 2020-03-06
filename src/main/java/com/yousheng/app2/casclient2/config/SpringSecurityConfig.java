package com.yousheng.app2.casclient2.config;

import com.yousheng.app2.casclient2.component.SecurityMetaDataSource;
import com.yousheng.app2.casclient2.component.UserDetailsServiceImpl;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jasig.cas.client.authentication.AuthenticationFilter;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author:lq
 * @date: 2020/3/5
 * @time: 16:57
 */
@Configuration
@EnableWebSecurity
@AllArgsConstructor
@Slf4j
@EnableConfigurationProperties(CasClientConfigurationProperties.class)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class  SpringSecurityConfig extends WebSecurityConfigurerAdapter{

    private final CasClientConfigurationProperties configProps;

    private final UserDetailsServiceImpl userDetailsService;

    private final SecurityMetaDataSource securityMetaDataSource;


    @Bean
    public FilterRegistrationBean singleSignOutFilterBean(){
        final FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter(new SingleSignOutFilter());
        filterRegistrationBean.setEnabled(true);
        filterRegistrationBean.addUrlPatterns("/*");
        Map<String,String> initParameters = new HashMap<>(16);
        initParameters.put("casServerUrlPrefix", configProps.getServerUrlPrefix());
        filterRegistrationBean.setInitParameters(initParameters);
        filterRegistrationBean.setOrder(1);
        filterRegistrationBean.setName("singleFilter");
        System.out.println("================================singleFilter执行");
        return filterRegistrationBean;
    }

    @Bean
    public ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> singleSignOutHttpSessionListenerBean() {
        ServletListenerRegistrationBean<SingleSignOutHttpSessionListener> listenerRegistrationBean = new ServletListenerRegistrationBean<>();
        listenerRegistrationBean.setEnabled(true);
        listenerRegistrationBean.setListener(new SingleSignOutHttpSessionListener());
        listenerRegistrationBean.setOrder(3);
        System.out.println("================================singleListener执行");
        return listenerRegistrationBean;
    }

    /**
     * description:授权过滤器
     * @param: []
     * @return: org.springframework.boot.web.servlet.FilterRegistrationBean
     */
    @Bean
    public FilterRegistrationBean filterAuthenticationRegistration() {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(new AuthenticationFilter());
        // 设定匹配的路径
        registration.addUrlPatterns("/*");
        Map<String,String>  initParameters = new HashMap<>(16);
        initParameters.put("casServerLoginUrl", configProps.getServerLoginUrl());
        initParameters.put("serverName", configProps.getClientHostUrl());
        //忽略/logout的路径
        initParameters.put("ignorePattern", "/logout2/*");

        registration.setInitParameters(initParameters);
        // 设定加载的顺序
        registration.setOrder(1);
        return registration;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**","/css/**","/img/**","/*.ico",
                "/error","/api/user/info");
        //web.ignoring().antMatchers("/js/**","/css/**","/img/**","/*.ico",,"/home");
        //web.ignoring().antMatchers("/**");
//        super.configure(web);

    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        super.configure(auth);
        auth.authenticationProvider(casAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        log.info("配置Spring security");
        http.formLogin()
//                //指定登录页是”/login”
//                .loginPage("/login.html").permitAll()
//                .loginProcessingUrl("/login.do").permitAll()
//                .defaultSuccessUrl("/home",true)
//                .permitAll()
                //登录成功后可使用loginSuccessHandler()存储用户信息，可选。
                //.successHandler(loginSuccessHandler()).permitAll()
                .and()
                .logout().permitAll()
                .invalidateHttpSession(true)
                .and()
                //登录后记住用户，下次自动登录,数据库中必须存在名为persistent_logins的表
//                .rememberMe()
//                .tokenValiditySeconds(1209600)
//                .and()
                .csrf().disable()
                //其他所有资源都需要认证，登陆后访问
                .authorizeRequests().anyRequest().fullyAuthenticated();

        http.exceptionHandling().authenticationEntryPoint(casAuthenticationEntryPoint())
                .and()
                .addFilterAt(casAuthenticationFilter(),CasAuthenticationFilter.class)
                .addFilterBefore(casLogoutFilter(),LogoutFilter.class)
                .addFilterBefore(singleSignOutFilter(),CasAuthenticationFilter.class);

        http.addFilterBefore(filterSecurityInterceptor(),FilterSecurityInterceptor.class);
    }

    /**
     * 注意：这里不能加@Bean注解
     * @return
     * @throws Exception
     */
    public FilterSecurityInterceptor filterSecurityInterceptor() throws Exception {
        FilterSecurityInterceptor filterSecurityInterceptor=new FilterSecurityInterceptor();
        filterSecurityInterceptor.setSecurityMetadataSource(securityMetaDataSource);
        filterSecurityInterceptor.setAuthenticationManager(authenticationManager());
        filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
        return filterSecurityInterceptor;
    }

    /**
     * 认证入口
     *  <p>
     *    <b>Note:</b>浏览器访问不可直接填客户端的login请求,若如此则会返回Error页面，无法被此入口拦截
     *  </p>
     * @return
     */
    @Bean
    public CasAuthenticationEntryPoint casAuthenticationEntryPoint(){
        CasAuthenticationEntryPoint casAuthenticationEntryPoint=new CasAuthenticationEntryPoint();
        casAuthenticationEntryPoint.setLoginUrl(configProps.getServerLoginUrl());
        casAuthenticationEntryPoint.setServiceProperties(serviceProperties());
        return casAuthenticationEntryPoint;
    }

    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties serviceProperties=new ServiceProperties();
        serviceProperties.setService(configProps.getClientHostUrl()+"/api/user/info");
        serviceProperties.setAuthenticateAllArtifacts(true);
        return serviceProperties;
    }

    public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
        CasAuthenticationFilter casAuthenticationFilter=new CasAuthenticationFilter();
        casAuthenticationFilter.setAuthenticationManager(authenticationManager());
        casAuthenticationFilter.setFilterProcessesUrl("/api/user/info");
        return casAuthenticationFilter;
    }

    @Bean
    public CasAuthenticationProvider casAuthenticationProvider(){
        CasAuthenticationProvider casAuthenticationProvider=new CasAuthenticationProvider();
        casAuthenticationProvider.setAuthenticationUserDetailsService(userDetailsService);

        casAuthenticationProvider.setServiceProperties(serviceProperties());
        casAuthenticationProvider.setTicketValidator(cas30ServiceTicketValidator());
        casAuthenticationProvider.setKey("casAuthenticationProviderKey");
        return casAuthenticationProvider;
    }

    @Bean
    public Cas30ServiceTicketValidator cas30ServiceTicketValidator() {
        return new Cas30ServiceTicketValidator(configProps.getServerUrlPrefix());
    }

    public SingleSignOutFilter singleSignOutFilter(){
        SingleSignOutFilter singleSignOutFilter=new SingleSignOutFilter();
        singleSignOutFilter.setCasServerUrlPrefix(configProps.getServerUrlPrefix());
        singleSignOutFilter.setIgnoreInitConfiguration(true);
        return singleSignOutFilter;
    }

    public LogoutFilter casLogoutFilter(){
        LogoutFilter logoutFilter = new LogoutFilter(configProps.getServerUrlPrefix()+"/logout?service="+configProps.getClientHostUrl(), new SecurityContextLogoutHandler());
        logoutFilter.setFilterProcessesUrl("/logout");
        return logoutFilter;
    }


    /**
     * 定义决策管理器，这里可直接使用内置的AffirmativeBased选举器，
     * 如果需要，可自定义，继承AbstractAccessDecisionManager，实现decide方法即可
     * @return
     */
    @Bean
    public AccessDecisionManager affirmativeBased(){
        log.info("正在创建决策管理器");
        List<AccessDecisionVoter<? extends Object>> voters=new ArrayList<>();
        voters.add(roleVoter());
        return new AffirmativeBased(voters);
    }

    /**
     * 定义选举器
     * @return
     */
    @Bean
    public RoleVoter roleVoter(){
        //这里使用角色选举器
        RoleVoter voter=new RoleVoter();
        log.info("正在创建选举器");
        voter.setRolePrefix("AUTH_");
        log.info("已将角色选举器的前缀修改为AUTH_");
        return voter;
    }

    /**
     * 重写AuthenticationManager获取的方法并且定义为Bean
     * @return
     * @throws Exception
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        //指定密码加密所使用的加密器为passwordEncoder()
        //需要将密码加密后写入数据库
//        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
//        auth.eraseCredentials(false);
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(4);
    }

}
