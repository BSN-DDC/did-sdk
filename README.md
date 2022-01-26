### 一、说明
BSN DID 是平台方的链上身份凭证标识，关联平台方的业务开通凭证、链账户以及其下终端用户的链账户，是平台方开展 DDC 应用和管理业务的基础标识。SDK 内包含注册 DID、更新密钥、验证 DID 三个方法，平台方只需注册一次 DID 即可，所以需妥善保存和备份好 BSN DID 的控制私钥，如私钥丢失或泄漏，通过更新密钥方法重新生成 BSN DID 的控制私钥。


### 二、要求
Java 1.8 最新版本(小版本大于200)


### 三、SDK 依赖的 JAR 包


``` 
          <dependency>
            <groupId>org.apache.directory.studio</groupId>
            <artifactId>org.apache.commons.codec</artifactId>
            <version>1.8</version>
        </dependency>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-lang3</artifactId>
            <version>3.5</version>
        </dependency>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.79</version>
        </dependency>
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcprov-jdk15on</artifactId>
            <version>1.68</version>
        </dependency>
        <dependency>
            <groupId>cn.hutool</groupId>
            <artifactId>hutool-all</artifactId>
            <version>5.6.3</version>
        </dependency>
        <dependency>
            <groupId>org.fisco-bcos.java-sdk</groupId>
            <artifactId>java-sdk</artifactId>
            <version>2.7.0</version>
        </dependency>
        <dependency>
            <groupId>org.fisco-bcos</groupId>
            <artifactId>web3sdk</artifactId>
            <version>2.6.4</version>
        </dependency>
        <dependency>
            <groupId>com.squareup.okhttp3</groupId>
            <artifactId>okhttp</artifactId>
            <version>4.9.0</version>
        </dependency>
        <dependency>
            <groupId>com.squareup.okhttp3</groupId>
            <artifactId>logging-interceptor</artifactId>
            <version>4.9.0</version>
        </dependency>
        <dependency>
            <groupId>org.web3j</groupId>
            <artifactId>core</artifactId>
            <version>4.8.4</version>
        </dependency>
        <dependency>
            <groupId>org.web3j</groupId>
            <artifactId>crypto</artifactId>
            <version>4.8.4</version>
        </dependency>
        <dependency>
      	    <groupId>junit</groupId>
      	    <artifactId>junit</artifactId>
      	    <version>3.8.1</version>
      	    <scope>test</scope>
        </dependency>
```


### 四、用法

DidClientTest.java

```java
package com.reddate.did;

import org.junit.Test;

import com.alibaba.fastjson.JSONObject;
import com.reddate.did.sdk.DidClient;
import com.reddate.did.sdk.param.req.DidSign;
import com.reddate.did.sdk.param.req.ResetDidAuth;
import com.reddate.did.sdk.param.resp.DidDataWrapper;
import com.reddate.did.sdk.protocol.common.KeyPair;
import com.reddate.did.sdk.util.ECDSAUtils;

import static org.junit.Assert.*;

public class DidClientTest {
	
	private DidClient getDidClient() {
		DidClient didClient = new DidClient();
		return didClient;
	}
	
	@Test   
	public void generateDidtest() {
		DidClient didClient = this.getDidClient();
		DidDataWrapper didDataWrapper = didClient.createDid();
		System.out.println("=================="+JSONObject.toJSONString(didDataWrapper));
		assertNotNull(didDataWrapper);
		assertNotNull(didDataWrapper.getDid());
		assertNotNull(didDataWrapper.getDocument());
		assertNotNull(didDataWrapper.getAuthKeyInfo());
		assertNotNull(didDataWrapper.getRecyKeyInfo());
	} 
	
	@Test   
	public void resetDidAuthTest() throws InterruptedException {
		DidClient didClient = this.getDidClient();
		DidDataWrapper didDataWrapper = didClient.createDid();
		
		ResetDidAuth restDidAuth = new ResetDidAuth();
		restDidAuth.setDid(didDataWrapper.getDid());
		KeyPair resetDidAuthKey = new KeyPair();
		resetDidAuthKey.setPrivateKey(didDataWrapper.getRecyKeyInfo().getPrivateKey());
		resetDidAuthKey.setPublicKey(didDataWrapper.getRecyKeyInfo().getPublicKey());
		resetDidAuthKey.setType(didDataWrapper.getRecyKeyInfo().getType());
		restDidAuth.setRecoveryKey(resetDidAuthKey);
		
		Thread.currentThread().sleep(2000);
		
		KeyPair newKeyPair = didClient.resetDidAuth(restDidAuth);
		
		assertNotNull(newKeyPair);
		assertNotNull(newKeyPair.getPrivateKey());
		assertNotNull(newKeyPair.getPublicKey());
		assertNotNull(newKeyPair.getType());
	} 
	
	@Test   
	public void resetDidAuthTest2() throws Exception {
		DidClient didClient = this.getDidClient();
		DidDataWrapper didDataWrapper = didClient.createDid();
		
		ResetDidAuth restDidAuth = new ResetDidAuth();
		restDidAuth.setDid(didDataWrapper.getDid());
		restDidAuth.setPrimaryKeyPair(ECDSAUtils.createKey());
		KeyPair resetDidAuthKey = new KeyPair();
		resetDidAuthKey.setPrivateKey(didDataWrapper.getRecyKeyInfo().getPrivateKey());
		resetDidAuthKey.setPublicKey(didDataWrapper.getRecyKeyInfo().getPublicKey());
		resetDidAuthKey.setType(didDataWrapper.getRecyKeyInfo().getType());
		restDidAuth.setRecoveryKey(resetDidAuthKey);
		
		Thread.currentThread().sleep(2000);
		
		KeyPair newKeyPair = didClient.resetDidAuth(restDidAuth);
		
		assertNotNull(newKeyPair);
		assertNotNull(newKeyPair.getPrivateKey());
		assertNotNull(newKeyPair.getPublicKey());
		assertNotNull(newKeyPair.getType());
	} 
	
	@Test   
	public void verifyDIdSign() throws Exception {
		DidClient didClient = this.getDidClient();
		DidDataWrapper didDataWrapper = didClient.createDid();
		
		DidSign didSign = new DidSign();
		didSign.setDid(didDataWrapper.getDid());
		didSign.setDidSign(didDataWrapper.getDidSign());
		
		Boolean verify = didClient.verifyDIdSign(didSign);
		
		assertTrue(verify);
	} 
	
}

```

### 五、DID签名
DID标识符签名，默认签名使用了Secp256k1算法。

```java
ResultData<CreateDidData> createDoc = createDidDocument();
if(!createDoc.isSuccess()) {
	return ResultData.error(createDoc.getCode(),createDoc.getMsg(), DidDataWrapper.class);
}
logger.debug("create did information is :"+JSONObject.toJSONString(createDoc));
		
String didSign = null;
try {
	didSign = ECDSAUtils.sign(createDoc.getData().getDid(), createDoc.getData().getAuthKeyInfo().getPrivateKey());
} catch (Exception e) {
	e.printStackTrace();
	throw new DidException(ErrorMessage.GENERATE_DID_FAIL.getCode(),ErrorMessage.GENERATE_DID_FAIL.getMessage());
}
```


### 六、默认全局配置
所有请求方法都有如下的全局配置。

```java
private static final String DID_SERVICE_URL = "https://didservice.bsngate.com:18602";
private static final String DID_SERVICE_PROJECT_ID = "8320935187";
private static final String DID_SERVICE_TOKEN = "3wxYHXwAm57grc9JUr2zrPHt9HC";

public DidClient() {
	didService = new DidService(DID_SERVICE_URL, DID_SERVICE_PROJECT_ID, DID_SERVICE_TOKEN); 
}
		
RequestBody requestBody = RequestBody.create(JSONObject.toJSONString(requestParam), JSON);
Request request = new Request.Builder()
		.url(url)
		.post(requestBody)
		.addHeader("token", token)
		.addHeader("projectId", requestParam.getProjectId())
	 	.build();
```


### 七、配置超时时间

配置超时时间，默认的连接超时时间是20秒，默认的读超时时间是60秒。

```java
OkHttpClient client = new OkHttpClient.Builder()
		.connectTimeout(20, TimeUnit.SECONDS)
		.readTimeout(60, TimeUnit.SECONDS)
		.build();
```


