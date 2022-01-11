package com.reddate.did.sdk.service;

import java.util.Objects;
import java.util.concurrent.TimeoutException;

import cn.hutool.core.util.ObjectUtil;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.reddate.did.sdk.constant.ErrorMessage;
import com.reddate.did.sdk.constant.ServiceURL;
import com.reddate.did.sdk.exception.DidException;
import com.reddate.did.sdk.param.req.DidSign;
import com.reddate.did.sdk.param.req.ResetDidAuth;
import com.reddate.did.sdk.param.resp.DidDataWrapper;
import com.reddate.did.sdk.param.resp.DocumentInfo;
import com.reddate.did.sdk.protocol.common.BaseDidDocument;
import com.reddate.did.sdk.protocol.common.DidDocument;
import com.reddate.did.sdk.protocol.common.KeyPair;
import com.reddate.did.sdk.protocol.common.Proof;
import com.reddate.did.sdk.protocol.request.DidDocSotreReq;
import com.reddate.did.sdk.protocol.request.DidDocumentReq;
import com.reddate.did.sdk.protocol.request.DidSignWrapper;
import com.reddate.did.sdk.protocol.request.RequestParam;
import com.reddate.did.sdk.protocol.request.ResetDidWrapper;
import com.reddate.did.sdk.protocol.response.CreateDidData;
import com.reddate.did.sdk.protocol.response.ResultData;
import com.reddate.did.sdk.util.DidUtils;
import com.reddate.did.sdk.util.ECDSAUtils;
import com.reddate.did.sdk.util.HttpUtils;

/**
 * 
 * The did module implement class,
 * 
 * this class contain the generated did, store did document on chain,
 * query did document,reset did authority main key function implement
 * 
 * 
 *
 */
public class DidService extends BaseService {

	public DidService(String url, String projectId, String token) {
		super(url, projectId,token);
	}

	private static final Logger logger = LoggerFactory.getLogger(DidService.class);
	
	
	/**
	 * 
	 * Create did document and store this document on block chain if choose store on block chain.
	 * 
	 * @param isStorageOnChain Store generated did document store on block chain 
	 * @return The did Identifier, generated did document and key pair.
	 */
	public ResultData<DidDataWrapper> generateDid(Boolean isStorageOnChain) {
		if (isStorageOnChain == null){
			throw new DidException(ErrorMessage.PARAMETER_IS_EMPTY.getCode(),"storage on chain is empty");
		}
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
		
		if(isStorageOnChain) {
			ResultData<Boolean> sotreDoc = storeDidDocumentOnChain(createDoc.getData().getDidDocument());
			if(!sotreDoc.isSuccess()) {
				String msg = sotreDoc.getMsg();
				if(msg == null || msg.trim().isEmpty()) {
					msg = "store did document on chain failed";
				}
				return ResultData.error(sotreDoc.getCode(),msg, DidDataWrapper.class);
			}
		}
		
		DidDataWrapper dataWrapper =  new DidDataWrapper();
		dataWrapper.setDid(createDoc.getData().getDid());
		dataWrapper.setAuthKeyInfo(createDoc.getData().getAuthKeyInfo());
		dataWrapper.setRecyKeyInfo(createDoc.getData().getRecyKeyInfo());
		DocumentInfo documentInfo  = new DocumentInfo();
		documentInfo.setDid(createDoc.getData().getDidDocument().getDid());
		documentInfo.setAuthentication(createDoc.getData().getDidDocument().getAuthentication());
		documentInfo.setRecovery(createDoc.getData().getDidDocument().getRecovery());
		documentInfo.setCreated(createDoc.getData().getDidDocument().getCreated());
		documentInfo.setUpdated(createDoc.getData().getDidDocument().getUpdated());
		documentInfo.setVersion(createDoc.getData().getDidDocument().getVersion());
		documentInfo.setProof(createDoc.getData().getDidDocument().getProof());
		dataWrapper.setDocument(documentInfo);
		dataWrapper.setDidSign(didSign);
		
		return ResultData.success(dataWrapper);
	}
	
	
	/**
	 * 
	 * Reset the main public key in the did document on block chain. 
	 * this function first validate the recovery key, 
	 * after recovery pass, then reset the main public key in this document on block chain.
	 * 
	 * 
	 * @param restDidAuth  Rest the did document key information.
	 * @return Return the reset main public key result
	 */
	public ResultData<KeyPair> resetDidAuth(ResetDidAuth resetDidAuth) throws Exception{
		if (ObjectUtil.isEmpty(resetDidAuth)){
			throw new DidException(ErrorMessage.PARAMETER_IS_EMPTY.getCode(),"reset did auth is empty");
		}
		if (StringUtils.isEmpty(resetDidAuth.getDid())){
			throw new DidException(ErrorMessage.PARAMETER_IS_EMPTY.getCode(),"did is empty");
		}

		if (ObjectUtil.isEmpty(resetDidAuth.getRecoveryKey())){
			throw new DidException(ErrorMessage.PARAMETER_IS_EMPTY.getCode(),"recovery key is empty");
		}
		if (ObjectUtil.isEmpty(resetDidAuth.getRecoveryKey().getPrivateKey())){
			throw new DidException(ErrorMessage.PARAMETER_IS_EMPTY.getCode(),"private key is empty");
		}
		if (ObjectUtil.isEmpty(resetDidAuth.getRecoveryKey().getType())){
			throw new DidException(ErrorMessage.PARAMETER_IS_EMPTY.getCode(),"type key is empty");
		}
		if (ObjectUtil.isEmpty(resetDidAuth.getRecoveryKey().getPublicKey())){
			throw new DidException(ErrorMessage.PARAMETER_IS_EMPTY.getCode(),"public key is empty");
		}
		ResultData<DidDocument> queryDidDocument = null;
		try {
			queryDidDocument = this.getDidDocument(resetDidAuth.getDid());
		} catch (DidException e1) {
			throw new DidException(e1.getCode(),e1.getMessage());
		} catch (Exception e1) {
			throw new DidException(ErrorMessage.UNKNOWN_ERROR.getCode(),"query did document on chian failed: " + e1.getMessage());
		}
		if(!queryDidDocument.isSuccess()) {
			throw new DidException(queryDidDocument.getCode(),queryDidDocument.getMsg());
		}
		
		String recoveryPublicKey = null;
		try {
			recoveryPublicKey = ECDSAUtils.getPublicKey(resetDidAuth.getRecoveryKey().getPrivateKey());
		} catch (Exception e2) {
			e2.printStackTrace();
		}
		
		if(recoveryPublicKey == null || !recoveryPublicKey.equals(queryDidDocument.getData().getRecovery().getPublicKey())) {
			throw new DidException(ErrorMessage.RECOVERY_KEY_INCORRECT.getCode(),ErrorMessage.RECOVERY_KEY_INCORRECT.getMessage());
		}
		
		DidDocument didDoc = queryDidDocument.getData();
		KeyPair keyPair = resetDidAuth.getPrimaryKeyPair();
		if(resetDidAuth.getPrimaryKeyPair() == null 
			|| resetDidAuth.getPrimaryKeyPair().getPrivateKey() == null || resetDidAuth.getPrimaryKeyPair().getPrivateKey().trim().isEmpty()
			|| resetDidAuth.getPrimaryKeyPair().getPublicKey() == null || resetDidAuth.getPrimaryKeyPair().getPublicKey().trim().isEmpty() 
			|| resetDidAuth.getPrimaryKeyPair().getType() == null || resetDidAuth.getPrimaryKeyPair().getType().trim().isEmpty()) {
			keyPair = ECDSAUtils.createKey();
		}else {
			String publicKey = null;
			try {
				publicKey = ECDSAUtils.getPublicKey(resetDidAuth.getPrimaryKeyPair().getPrivateKey());
			} catch (Exception e) {
				e.printStackTrace();
			}
			if(publicKey == null || !publicKey.equals(resetDidAuth.getPrimaryKeyPair().getPublicKey())) {
				throw new DidException(ErrorMessage.PRK_PUK_NOT_MATCH.getCode(),ErrorMessage.PRK_PUK_NOT_MATCH.getMessage());
			}
		}
		
		DidDocument newDidDocument = DidUtils.renewDidDocument(didDoc, keyPair);
		String signValue = ECDSAUtils.sign(JSONArray.toJSON(newDidDocument).toString(), keyPair.getPrivateKey());
		if(StringUtils.isBlank(signValue)){
			throw new DidException(ErrorMessage.SIGNATURE_FAILED.getCode(),ErrorMessage.SIGNATURE_FAILED.getMessage());
		}

		// Assembling sign
		Proof proof = new Proof();
		proof.setType(ECDSAUtils.TYPE);
		proof.setCreator(newDidDocument.getDid());
		proof.setSignatureValue(signValue);
		newDidDocument.setProof(proof);
		
		String authPublicKeySign = null;
		try {
			authPublicKeySign = ECDSAUtils.sign(recoveryPublicKey, resetDidAuth.getRecoveryKey().getPrivateKey());
		} catch (Exception e1) {
			e1.printStackTrace();
			throw new DidException(ErrorMessage.SIGNATURE_FAILED.getCode(),ErrorMessage.SIGNATURE_FAILED.getMessage());
		}
		
		String signature = com.reddate.did.sdk.util.Signatures.get().setInfo(this.getProjectId(),didDoc.getDid())
				.add("document", newDidDocument)
				.add("authPubKeySign", authPublicKeySign)
				.sign(resetDidAuth.getRecoveryKey().getPrivateKey());
				
		RequestParam<ResetDidWrapper> reqParam = new RequestParam<>(this.getProjectId(),newDidDocument.getDid());
		ResetDidWrapper resetDidWrapper = new ResetDidWrapper();
		resetDidWrapper.setDidDoc(didDoc);
		resetDidWrapper.setAuthPubKeySign(authPublicKeySign);
		reqParam.setData(resetDidWrapper);
		reqParam.setSign(signature);
		
		ResultData<KeyPair> restAuthResult = HttpUtils.postCall(this.getUrl()+ServiceURL.REST_DID_AUTH,this.getToken(),reqParam, KeyPair.class);
		if(restAuthResult.isSuccess()) {
			return ResultData.success(keyPair);
		}else {
			return ResultData.error(restAuthResult.getCode(),restAuthResult.getMsg(), KeyPair.class);
		}
	}
	
	/**
	 * 
	 * Verify the sign value of the did identify is correct or not  by the did identify related document's public key.
	 * 
	 *
	 * @param didSign the did identify and did identify's sign value
	 * @return Return the verify did identify result
	 */
	public ResultData<Boolean> verifyDIdSign(DidSign didSign) {
		if (didSign == null){
			throw new DidException(ErrorMessage.PARAMETER_IS_EMPTY.getCode(),"did and did sign is empty");
		}
		if (didSign.getDid() == null || didSign.getDid().trim().isEmpty()){
			throw new DidException(ErrorMessage.PARAMETER_IS_EMPTY.getCode(),"did is empty");
		}
		
		if (didSign.getDidSign() == null || didSign.getDidSign().trim().isEmpty()){
			throw new DidException(ErrorMessage.PARAMETER_IS_EMPTY.getCode(),"did sign is empty");
		}
		
		RequestParam<DidSignWrapper> reqParam = new RequestParam<>(this.getProjectId(),didSign.getDid());
		DidSignWrapper didSignWrapper = new DidSignWrapper();
		didSignWrapper.setDid(didSign.getDid());
		didSignWrapper.setDidSign(didSign.getDidSign());
		reqParam.setData(didSignWrapper);
		
		ResultData<Boolean> verifyResult = HttpUtils.postCall(this.getUrl()+ServiceURL.VERIFY_DID_SIGN,this.getToken(),reqParam, Boolean.class);
		return verifyResult;
	}
	
	/**
	 * 
	 * Generated one did document
	 * 
	 * 
	 * @return The did Identifier, generated did document and key pair.
	 */
	private ResultData<CreateDidData> createDidDocument() {
		try {
			KeyPair primaryKeyPair = ECDSAUtils.createKey();
			KeyPair alternateKeyPair = ECDSAUtils.createKey();
			if (StringUtils.isBlank(primaryKeyPair.getPublicKey())
					|| StringUtils.isBlank(primaryKeyPair.getPrivateKey())
					|| StringUtils.isBlank(alternateKeyPair.getPublicKey())
					|| StringUtils.isBlank(alternateKeyPair.getPrivateKey())
			) {
				throw new DidException(ErrorMessage.GENERATE_DID_FAIL.getCode(),ErrorMessage.GENERATE_DID_FAIL.getMessage());
			}

			BaseDidDocument baseDidDocument = DidUtils.generateBaseDidDocument(primaryKeyPair, alternateKeyPair);

			String didIdentifier = DidUtils.generateDidIdentifierByBaseDidDocument(baseDidDocument);
			if(StringUtils.isBlank(didIdentifier)){				
				throw new DidException(ErrorMessage.GENERATE_DID_FAIL.getCode(),ErrorMessage.GENERATE_DID_FAIL.getMessage());
			}

			String did = DidUtils.generateDidByDidIdentifier(didIdentifier);
			if(StringUtils.isBlank(did)){
				throw new DidException(ErrorMessage.GENERATE_DID_FAIL.getCode(),ErrorMessage.GENERATE_DID_FAIL.getMessage());
			}

			DidDocument didDocument = DidUtils.generateDidDocument(primaryKeyPair, alternateKeyPair, did);
			if(Objects.isNull(didDocument)){
				throw new DidException(ErrorMessage.GENERATE_DID_FAIL.getCode(),ErrorMessage.GENERATE_DID_FAIL.getMessage());
			}

			String signValue = ECDSAUtils.sign(JSONArray.toJSON(didDocument).toString(), primaryKeyPair.getPrivateKey());
			if(StringUtils.isBlank(signValue)){
				throw new DidException(ErrorMessage.GENERATE_DID_FAIL.getCode(),ErrorMessage.GENERATE_DID_FAIL.getMessage());
			}

			Proof proof = new Proof();
			proof.setType(ECDSAUtils.TYPE);
			proof.setCreator(did);
			proof.setSignatureValue(signValue);
			didDocument.setProof(proof);

			CreateDidData createDidData = new CreateDidData();
			createDidData.setDid(did);
			createDidData.setAuthKeyInfo(primaryKeyPair);
			createDidData.setRecyKeyInfo(alternateKeyPair);
			createDidData.setDidDocument(didDocument);
			return ResultData.success(createDidData);
		}catch (TimeoutException e){
			e.printStackTrace();
			logger.error(e.getMessage(),e);
			return ResultData.error(ErrorMessage.GENERATE_DID_FAIL.getCode(),ErrorMessage.GENERATE_DID_FAIL.getMessage(), CreateDidData.class);
		}catch (Exception e){
			e.printStackTrace();
			logger.error(e.getMessage(),e);
			return ResultData.error(ErrorMessage.GENERATE_DID_FAIL.getCode(),ErrorMessage.GENERATE_DID_FAIL.getMessage(), CreateDidData.class);
		}
	}
	
	
	/**
	 * 
	 * Store this did document to block chain by request the did service
	 * 
	 * 
	 * @param document The did document
	 * @return On chain result 
	 */
	private ResultData<Boolean> storeDidDocumentOnChain(DidDocument document){
		RequestParam<DidDocSotreReq> reqParam = new RequestParam<>(this.getProjectId(),document.getDid());
		DidDocSotreReq didDocSotreReq = new DidDocSotreReq();
		didDocSotreReq.setDidDoc(document);
		reqParam.setData(didDocSotreReq);
		
		ResultData<Boolean> regResult = HttpUtils.postCall(this.getUrl()+ServiceURL.PUT_DID_ON_CHAIN,this.getToken(),reqParam, Boolean.class);
		if(regResult.isSuccess()) {
			return ResultData.success(null);
		}else {
			return ResultData.error(regResult.getCode(),regResult.getMsg(), Boolean.class);
		}	
	}
	
	
	/**
	 * 
	 * Query the did document information on block chain
	 * 
	 * @param did Identifier
	 * @return did document detail information
	 */
	private ResultData<DidDocument> getDidDocument(String did){
		if (StringUtils.isEmpty(did)){
			throw new DidException(ErrorMessage.PARAMETER_IS_EMPTY.getCode(),"did is empty");
		}
		RequestParam<DidDocumentReq> reqParam = new RequestParam<>(this.getProjectId(),did);
		DidDocumentReq didDocumentReq = new DidDocumentReq();
		didDocumentReq.setDid(did);
		reqParam.setData(didDocumentReq);
		ResultData<DidDocument> regResult = HttpUtils.postCall(this.getUrl()+ServiceURL.GET_DID_DOCUMENT,this.getToken(),reqParam, DidDocument.class);
		
		if(regResult.isSuccess()) {
			return ResultData.success(regResult.getData());
		}else {
			return ResultData.error(regResult.getCode(),regResult.getMsg(), DidDocument.class);
		}
	}
	
	
}
