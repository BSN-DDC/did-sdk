package com.reddate.did.sdk.util;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * SM2 签名加密工具
 */
public class SM2Util {

    public static final SM2Engine.Mode DIGEST = SM2Engine.Mode.C1C3C2;
    public static final String ALGORITHM = "SM2";
    private static final Logger log = LoggerFactory.getLogger(SM2Util.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 私钥转换为 {@link ECPrivateKeyParameters}
     *
     * @param key key
     * @return
     * @throws InvalidKeyException
     */
    public static ECPrivateKeyParameters privateKeyToParams(String algorithm, byte[] key) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        PrivateKey privateKey = generatePrivateKey(algorithm, key);
        return (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(privateKey);
    }

    /**
     * 生成私钥
     *
     * @param algorithm 算法
     * @param key       key
     * @return
     */
    public static PrivateKey generatePrivateKey(String algorithm, byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new PKCS8EncodedKeySpec(key);
        algorithm = getAlgorithmAfterWith(algorithm);
        return getKeyFactory(algorithm).generatePrivate(keySpec);
    }


    /**
     * 公钥转换为 {@link ECPublicKeyParameters}
     *
     * @param key key
     * @return
     * @throws InvalidKeyException
     */
    public static ECPublicKeyParameters publicKeyToParams(String algorithm, byte[] key) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        PublicKey publicKey = generatePublicKey(algorithm, key);
        return (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(publicKey);
    }

    /**
     * 生成公钥
     *
     * @param algorithm 算法
     * @param key       key
     * @return
     */
    public static PublicKey generatePublicKey(String algorithm, byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new X509EncodedKeySpec(key);
        algorithm = getAlgorithmAfterWith(algorithm);
        return getKeyFactory(algorithm).generatePublic(keySpec);
    }

    /**
     * 获取用于密钥生成的算法<br>
     * 获取XXXwithXXX算法的后半部分算法，如果为ECDSA或SM2，返回算法为EC
     *
     * @param algorithm XXXwithXXX算法
     * @return 算法
     */
    private static String getAlgorithmAfterWith(String algorithm) {
//        int indexOfWith = StringUtils.lastIndexOfIgnoreCase(algorithm, "with");
//        if (indexOfWith > 0) {
//            algorithm = StringUtils.substring(algorithm, indexOfWith + "with".length());
//        }
        if ("ECDSA".equalsIgnoreCase(algorithm) || ALGORITHM.equalsIgnoreCase(algorithm)) {
            algorithm = "EC";
        }
        return algorithm;
    }

    /**
     * 获取{@link KeyFactory}
     *
     * @param algorithm 非对称加密算法
     * @return {@link KeyFactory}
     */
    private static KeyFactory getKeyFactory(String algorithm) throws NoSuchAlgorithmException {
        final Provider provider = new BouncyCastleProvider();
        return KeyFactory.getInstance(algorithm, provider);
    }

    /**
     * 私钥签名
     *
     * @param privateKey 私钥
     * @param content    待签名内容
     * @return
     */
    public static String hexSign(String privateKey, String content) throws CryptoException {
        //待签名内容转为字节数组
        byte[] message = content.getBytes(StandardCharsets.UTF_8);

        //获取一条SM2曲线参数
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
        //构造domain参数
        ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(),
                sm2ECParameters.getG(), sm2ECParameters.getN());

        BigInteger privateKeyD = new BigInteger(privateKey, 16);
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKeyD, domainParameters);

        //创建签名实例
        SM2Signer sm2Signer = new SM2Signer();

        //初始化签名实例,带上ID,国密的要求,ID默认值:1234567812345678
        try {
            sm2Signer.init(true, new ParametersWithID(new ParametersWithRandom(privateKeyParameters, SecureRandom.getInstance("SHA1PRNG")), Strings.toByteArray("1234567812345678")));
        } catch (NoSuchAlgorithmException e) {
            log.error("签名时出现异常:", e);
        }
        sm2Signer.update(message, 0, message.length);
        //生成签名,签名分为两部分r和s,分别对应索引0和1的数组
        byte[] signBytes = sm2Signer.generateSignature();

        String sign = Hex.toHexString(signBytes);

        return sign;
    }


    /**
     * 验证签名
     *
     * @param publicKey 公钥
     * @param content   待签名内容
     * @param sign      签名值
     * @return
     */
    public static boolean hexVerify(String publicKey, String content, String sign) {
        //待签名内容
        byte[] message = content.getBytes(StandardCharsets.UTF_8);
        byte[] signData = Hex.decode(sign);

        // 获取一条SM2曲线参数
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
        // 构造domain参数
        ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(),
                sm2ECParameters.getG(),
                sm2ECParameters.getN());
        //提取公钥点
        ECPoint pukPoint = sm2ECParameters.getCurve().decodePoint(Hex.decode(publicKey));
        // 公钥前面的02或者03表示是压缩公钥，04表示未压缩公钥, 04的时候，可以去掉前面的04
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(pukPoint, domainParameters);
        //创建签名实例
        SM2Signer sm2Signer = new SM2Signer();
        ParametersWithID parametersWithID = new ParametersWithID(publicKeyParameters, Strings.toByteArray("1234567812345678"));
        sm2Signer.init(false, parametersWithID);
        sm2Signer.update(message, 0, message.length);
        //验证签名结果
        boolean verify = sm2Signer.verifySignature(signData);
        return verify;
    }


    /**
     * <p>软验签</p>
     * @param publicKey
     * @param content
     * @param sign
     * @return boolean
     */
    public static boolean softHexVerify(String publicKey, String content, byte[] sign) throws InvalidAlgorithmParameterException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException{
        PublicKey publicKey1 = converPublic(Hex.decode(publicKey));
        SM2ParameterSpec parameterSpec = new SM2ParameterSpec("1234567812345678".getBytes());
        Signature verify = Signature.getInstance("SM3WithSM2","BC");
        verify.setParameter(parameterSpec);
        verify.initVerify(publicKey1);
        verify.update(content.getBytes(StandardCharsets.UTF_8));
        return verify.verify(sign);
    }


    public static PublicKey converPublic(byte[] publicKeyBytes) throws IOException {
        ECNamedCurveParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        if (publicKeyBytes.length == 65) {
            publicKeyBytes = ByteUtils.subArray(publicKeyBytes, 1);
        }
        byte[] publicKeyX = new byte[32];
        byte[] publicKeyY = new byte[32];
        System.arraycopy(publicKeyBytes, 0, publicKeyX, 0, 32);
        System.arraycopy(publicKeyBytes, 32, publicKeyY, 0, 32);
        ECCurve curve = ecParameterSpec.getCurve();
        ECPoint point = curve.createPoint(new BigInteger(1,publicKeyX),new BigInteger(1,publicKeyY));
        ECPublicKeySpec keySpec = new ECPublicKeySpec(point, ecParameterSpec);
        return new BCECPublicKey("EC", keySpec, BouncyCastleProvider.CONFIGURATION);
    }

    public static PairKey getSm2Keys(boolean compressed) {
        //获取一条SM2曲线参数
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
        //构造domain参数
        ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
        //1.创建密钥生成器
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        //2.初始化生成器,带上随机数
        try {
            keyPairGenerator.init(new ECKeyGenerationParameters(domainParameters, SecureRandom.getInstance("SHA1PRNG")));
        } catch (NoSuchAlgorithmException e) {
            log.error("生成公私钥对时出现异常:", e);
        }
        //3.生成密钥对
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
        ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters) asymmetricCipherKeyPair.getPublic();
        ECPoint ecPoint = publicKeyParameters.getQ();
        // 把公钥放入map中,默认压缩公钥
        // 公钥前面的02或者03表示是压缩公钥,04表示未压缩公钥,04的时候,可以去掉前面的04
        String publicKey = Hex.toHexString(ecPoint.getEncoded(compressed));
        ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
        BigInteger intPrivateKey = privateKeyParameters.getD();
        // 把私钥放入map中
        String privateKey = intPrivateKey.toString(16);
        return new PairKey(privateKey, publicKey);
    }

}