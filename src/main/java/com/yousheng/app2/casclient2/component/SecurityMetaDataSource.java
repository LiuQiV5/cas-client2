package com.yousheng.app2.casclient2.component;

import com.yousheng.app2.casclient2.config.CasClientConfigurationProperties;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.*;

/**
 * @author:lq
 * @date: 2020/3/5
 * @time: 16:51
 */
@Component
@AllArgsConstructor
@Slf4j
public class SecurityMetaDataSource implements FilterInvocationSecurityMetadataSource{



    private LinkedHashMap<String,Collection<ConfigAttribute>> metaData;

    @PostConstruct
    private void loadSecurityMetaData(){
        List<ConfigAttribute> base=new ArrayList<>();
        base.add(new SecurityConfig("AUTH_0"));
        metaData.put("/**",base);
    }

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        FilterInvocation invocation= (FilterInvocation) object;
        if (metaData==null){
            return new ArrayList<>(0);
        }
        String requestUrl = invocation.getRequestUrl();
        log.info("请求Url:{}",requestUrl);
        Iterator<Map.Entry<String, Collection<ConfigAttribute>>> iterator = metaData.entrySet().iterator();
        Collection<ConfigAttribute> rs=new ArrayList<>();
        while (iterator.hasNext()){
            Map.Entry<String, Collection<ConfigAttribute>> next = iterator.next();
            String url = next.getKey();
            Collection<ConfigAttribute> value = next.getValue();
            RequestMatcher requestMatcher=new AntPathRequestMatcher(url);
            if (requestMatcher.matches(invocation.getRequest())){
                rs = value;
                break;
            }
        }
        log.info("拦截认证权限为:{}",rs);
        return rs;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Collection<Collection<ConfigAttribute>> values = metaData.values();
        Collection<ConfigAttribute> all=new ArrayList<>();
        for (Collection<ConfigAttribute> each:values){
            each.forEach(configAttribute -> all.add(configAttribute));
        }
        return all;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }
}
