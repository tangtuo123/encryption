package cn.com.citydo.encrypt.response;

import cn.com.citydo.encrypt.annotation.Secret;
import cn.com.citydo.encrypt.utils.AESUtil;
import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.util.Map;
import java.util.Objects;

/**
 * @author ：
 * @date ：
 */
@Slf4j
@ControllerAdvice
public class EncryptResponseBodyAdvice implements ResponseBodyAdvice<Object> {

    @Override
    public boolean supports(MethodParameter methodParameter, Class<? extends HttpMessageConverter<?>> aClass) {
        // 对加了@Secret注解并且encrypt=true的方法响应数据进行加密处理
        return Objects.requireNonNull(methodParameter.getMethod()).isAnnotationPresent(Secret.class) && methodParameter.getMethod().getAnnotation(Secret.class).encrypt();
    }

    @Override
    public Object beforeBodyWrite(Object result, MethodParameter methodParameter, MediaType mediaType, Class<? extends HttpMessageConverter<?>> aClass, ServerHttpRequest serverHttpRequest, ServerHttpResponse serverHttpResponse) {
        Secret secret = methodParameter.getMethod().getAnnotation(Secret.class);
        String json = JSONObject.toJSONString(result);
        Map<String, Object> map = JSONObject.parseObject(json, Map.class);
        // 仅当请求成功时加密
        if (map != null && secret.successCode().equals(map.get("code").toString())) {
            String data = JSONObject.toJSONString(map.get(secret.dataField()));
            try {
                String encryptStr = AESUtil.encrypt(data);
                map.put(secret.dataField(), encryptStr);
            } catch (Exception e) {
                log.error(e.getMessage(), e);
                throw new RuntimeException(e);
            }
        }
        return map;
    }
}
