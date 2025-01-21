package org.example;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

@SpringBootTest
class DemoBackendApplicationTests {

    @Test
    void contextLoads () {
                String jwtKey = "abcdefghijklmn";                 //使用一个JWT秘钥进行加密
                Algorithm algorithm = Algorithm.HMAC256(jwtKey);  //创建HMAC256加密算法对象
                String jwtToken = JWT.create()
                        .withClaim("id", 1)   //向令牌中塞入自定义的数据
                        .withClaim("name", "lbw")
                        .withClaim("role", "nb")
                        .withExpiresAt(new Date(2025, Calendar.FEBRUARY, 1))  //JWT令牌的失效时间
                        .withIssuedAt(new Date())   //JWT令牌的签发时间
                        .sign(algorithm);    //使用上面的加密算法进行加密，完成签名
                System.out.println(jwtToken);   //得到最终的JWT令牌
            }


}
