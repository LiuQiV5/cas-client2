package com.yousheng.app2.casclient2.config;

import lombok.AllArgsConstructor;
import org.jasig.cas.client.authentication.AuthenticationFilter;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.util.HashMap;
import java.util.Map;


/**
 * @author ：lq
 * @date ：2020/3/3
 * @time：14:03
 */
@Configuration
@EnableConfigurationProperties(CasClientConfigurationProperties.class)
@AllArgsConstructor
public class CasClientConfiguration {

    private final CasClientConfigurationProperties configProps;

    /**
     * 配置登出过滤器
     * @return   FilterRegistrationBean
//     */
//    @Bean
//    public FilterRegistrationBean filterSingleRegistration() {
//        final FilterRegistrationBean registration = new FilterRegistrationBean();
//        registration.setFilter(new SingleSignOutFilter());
//        // 设定匹配的路径
//        registration.addUrlPatterns("/*");
//        Map<String,String> initParameters = new HashMap<>(16);
//        initParameters.put("casServerUrlPrefix", configProps.getServerUrlPrefix());
//        registration.setInitParameters(initParameters);
//        // 设定加载的顺序
//        registration.setOrder(1);
//        return registration;
//    }

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





}
