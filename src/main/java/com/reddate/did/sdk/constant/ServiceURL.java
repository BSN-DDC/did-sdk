package com.reddate.did.sdk.constant;

/**
 * The request URL constant of the did service in BSN.
 * 
 * 
 *
 */
public class ServiceURL {

	/**
	 * URL of create did service endpoint in BSN
	 * 
	 */
	public static final String PUT_DID_ON_CHAIN = "/did/putDoc";
	
	/**
	 * URL of query did document service endpoint in BSN
	 * 
	 */
	public static final String GET_DID_DOCUMENT = "/did/getDoc";
	
	/**
	 * URL of reset did document main authenticate service endpoint in BSN
	 * 
	 */
	public static final String REST_DID_AUTH = "/did/resetDidAuth";
	
	/**
	 * URL of verify did identifier sign service endpoint in BSN
	 * 
	 */
	public static final String VERIFY_DID_SIGN = "/did/verifyDIdSign";
	
}
