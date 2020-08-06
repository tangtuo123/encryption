package cn.com.citydo.encrypt.request;

import cn.com.citydo.encrypt.annotation.Secret;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import java.lang.reflect.Type;
import java.util.Objects;

/**
 * @author ：
 * @date ：
 */
@Slf4j
@RestControllerAdvice(annotations = RestController.class)
public class DecryptRequestBodyAdvice implements RequestBodyAdvice {

    @Override
    public boolean supports(MethodParameter methodParameter, Type type, Class<? extends HttpMessageConverter<?>> aClass) {
        // 对加了@Secret注解并且decrypt=true的方法请求数据进行解密处理
        return Objects.requireNonNull(methodParameter.getMethod()).isAnnotationPresent(Secret.class) && methodParameter.getMethod().getAnnotation(Secret.class).decrypt();
    }

    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage httpInputMessage, MethodParameter methodParameter, Type type, Class<? extends HttpMessageConverter<?>> aClass) {
        try {
            return new DecryptHttpInputMessage(httpInputMessage, "UTF-8");
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(e);

        }
    }

    @Override
    public Object afterBodyRead(Object o, HttpInputMessage httpInputMessage, MethodParameter methodParameter, Type type, Class<? extends HttpMessageConverter<?>> aClass) {
        return o;
    }

    @Override
    public Object handleEmptyBody(Object o, HttpInputMessage httpInputMessage, MethodParameter methodParameter, Type type, Class<? extends HttpMessageConverter<?>> aClass) {
        return o;
    }
}
