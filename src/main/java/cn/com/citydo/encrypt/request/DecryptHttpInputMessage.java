package cn.com.citydo.encrypt.request;

import cn.com.citydo.encrypt.utils.AESUtil;
import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;

import java.io.InputStream;
import java.util.Map;

/**
 * @author ：tangtuo
 * @date ：Created in 2020/7/14 10:57
 */
public class DecryptHttpInputMessage implements HttpInputMessage {

    private HttpHeaders headers;
    private InputStream body;

    private static final String PARAMETER_NAME = "encryptStr";

    @Override
    public InputStream getBody() {
        return body;
    }

    @Override
    public HttpHeaders getHeaders() {
        return headers;
    }

    public DecryptHttpInputMessage(HttpInputMessage inputMessage, String charset) throws Exception {
        //获取请求头内容
        this.headers = inputMessage.getHeaders();
        String bodyStr = IOUtils.toString(inputMessage.getBody(), charset);
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, String> map = objectMapper.readValue(bodyStr, Map.class);
        if (null == map || StringUtils.isBlank(map.get(PARAMETER_NAME))) {
            throw new RuntimeException("请求参数不能为空");
        }
        String encryptStr = map.get(PARAMETER_NAME);
        //直接对内容进行解密
        String decryptBody = AESUtil.decrypt(encryptStr);
        //数据写回
        this.body = IOUtils.toInputStream(decryptBody, charset);
    }
}
