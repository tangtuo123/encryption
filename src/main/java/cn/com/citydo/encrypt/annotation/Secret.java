package cn.com.citydo.encrypt.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @author :
 * @date ：
 * <p>对客户端部分安全性要求较高的接口进行加解密处理</p>
 */

@Target(value = ElementType.METHOD)
@Retention(value = RetentionPolicy.RUNTIME)
public @interface Secret {

    /**
     * 是否对响应参数进行加密
     *
     * @return
     */
    boolean encrypt() default true;

    /**
     * 是否对请求参数解密
     *
     * @return
     */
    boolean decrypt() default true;

    /**
     * 统一返回体中传数据的字段名
     *
     * @return
     */
    String dataField() default "data";

    /**
     * 请求成功时的code值
     *
     * @return
     */
    String successCode() default "200";
}
