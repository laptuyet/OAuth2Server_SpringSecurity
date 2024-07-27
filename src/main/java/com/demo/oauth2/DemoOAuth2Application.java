package com.demo.oauth2;

import com.demo.oauth2.config.RSAKeyRecord;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(value = {RSAKeyRecord.class})
public class DemoOAuth2Application {

	public static void main(String[] args) {
		SpringApplication.run(DemoOAuth2Application.class, args);
	}

}
