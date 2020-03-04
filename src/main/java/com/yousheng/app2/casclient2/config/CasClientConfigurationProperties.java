package com.yousheng.app2.casclient2.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import javax.validation.constraints.NotNull;

/**
 * @author ：lq
 * @date ：2020/3/3
 * @time：14:07
 */
@Data
@ConfigurationProperties(prefix = "cas", ignoreUnknownFields = false)
public class CasClientConfigurationProperties {

    /**
     * CAS server URL E.g. https://example.com/cas or https://cas.example. Required.
     * CAS 服务端 url 不能为空
     */
    @NotNull
    private String serverUrlPrefix;

    /**
     * CAS server login URL E.g. https://example.com/cas/login or https://cas.example/login. Required.
     * CAS 服务端登录地址  上面的连接 加上/login 该参数不能为空
     */
    @NotNull
    private String serverLoginUrl;

    /**
     * CAS-protected client application host URL E.g. https://myclient.example.com Required.
     * 当前客户端的地址
     */
    @NotNull
    private String clientHostUrl;

    /**
     * 忽略规则,访问那些地址 不需要登录
     */
    private String ignorePattern;

    /**
     * 自定义UrlPatternMatcherStrategy验证
     */
    private String ignoreUrlPatternType;

}
