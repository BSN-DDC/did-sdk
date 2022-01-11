package com.reddate.did.sdk;


import com.reddate.did.sdk.constant.ErrorMessage;
import com.reddate.did.sdk.exception.DidException;
import com.reddate.did.sdk.param.req.DidSign;
import com.reddate.did.sdk.param.req.ResetDidAuth;
import com.reddate.did.sdk.param.resp.DidDataWrapper;
import com.reddate.did.sdk.protocol.common.KeyPair;
import com.reddate.did.sdk.protocol.response.ResultData;
import com.reddate.did.sdk.service.DidService;
/**
 * 
 * Did SDK main class, all the BSN did service can be called by this class method.
 * 
 * Before call BSN did service, you need create did client instance.
 * for example:
 *  DidClient didClient = new DidClient();
 *  
 *
 */
public class DidClient {
	
	/**
	 * did service request url
	 */
	//private static final String DID_SERVICE_URL = "https://didservice.bsngate.com:18602";
	private static final String DID_SERVICE_URL = "http://117.107.141.162:19004";
	
	/**
	 * did service request project Id
	 */
	private static final String DID_SERVICE_PROJECT_ID = "8320935187";	
	
	/**
	 * did service request token
	 */
	private static final String DID_SERVICE_TOKEN = "3wxYHXwAm57grc9JUr2zrPHt9HC";
	
	/**
	 * Did module service logic implement class
	 * 
	 */
	private DidService didService;
		
	/**
	 * Did client construct
	 * 
	 * 
	 * @param url  BSN did service URL
	 * @param projectId  The project Id of BSN assign
	 * @param token The Token of BSN assign
	 */
	public DidClient() {
		didService = new DidService(DID_SERVICE_URL, DID_SERVICE_PROJECT_ID, DID_SERVICE_TOKEN); 
		//didService = new DidService("http://127.0.0.1:19004", DID_SERVICE_PROJECT_ID, DID_SERVICE_TOKEN); 
	}
	
	/**
	 * 
	 * Create did document and store this document on block chain if choose store on block chain.
	 * 
	 * @param isStorageOnChain Store generated did document store on block chain 
	 * @return The did Identifier, generated did document and key pair.
	 */
	public DidDataWrapper createDid() {
		ResultData<DidDataWrapper> genDidResult = null;
		try {
			genDidResult = didService.generateDid(true);
		} catch (DidException e) {
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
			throw new DidException(ErrorMessage.UNKNOWN_ERROR.getCode(),e.getMessage());
		}
		
		if(!genDidResult.isSuccess()) {
			throw new DidException(genDidResult.getCode(),genDidResult.getMsg());
		}
		
		return genDidResult.getData();
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
	public KeyPair resetDidAuth(ResetDidAuth restDidAuth) {
		ResultData<KeyPair> restAuth = null;
		try {
			restAuth = didService.resetDidAuth(restDidAuth);
		} catch (DidException e) {
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
			throw new DidException(ErrorMessage.UNKNOWN_ERROR.getCode(),e.getMessage());
		}
		
		if(!restAuth.isSuccess()) {
			throw new DidException(restAuth.getCode(),restAuth.getMsg());
		}

		return restAuth.getData();
	}
	
	/**
	 * 
	 * Verify the sign value of the did identify is correct or not  by the did identify related document's public key.
	 * 
	 *
	 * @param didSign the did identify and did identify's sign value
	 * @return Return the verify did identify result
	 */
	public Boolean verifyDIdSign(DidSign didSign) {
		ResultData<Boolean> verifyResult = null;
		try {
			verifyResult = didService.verifyDIdSign(didSign);
		} catch (DidException e) {
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
			throw new DidException(ErrorMessage.UNKNOWN_ERROR.getCode(),e.getMessage());
		}
		
		if(!verifyResult.isSuccess()) {
			throw new DidException(verifyResult.getCode(),verifyResult.getMsg());
		}
		
		return verifyResult.getData();
	}
}
