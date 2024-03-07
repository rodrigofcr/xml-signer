package com.github.rodrigofcr.xmlsigner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class XmlSignerApplication implements ApplicationRunner {

	private final Logger LOGGER = LoggerFactory.getLogger(XmlSignerApplication.class);
	private final SigningService signingService;

	public XmlSignerApplication(final SigningService signingService) {
		this.signingService = signingService;
	}

	public static void main(String[] args) {
		SpringApplication.run(XmlSignerApplication.class, args).close();
	}

	@Override
	public void run(final ApplicationArguments args) throws Exception {

		final String unsignedXml = "<AnyTag></AnyTag>";
		LOGGER.info("Unsigned XML: {}", unsignedXml);

		final String signedXml = signingService.signWithPKCS12Certificate(unsignedXml);
		LOGGER.info("Signed XML: {}", signedXml);

	}
}
