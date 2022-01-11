package com.reddate.did.sdk.constant;


public enum ErrorMessage {

	UNKNOWN_ERROR(9999, "unknown error"),
	PARAMETER_IS_EMPTY(1001, " is empty"),
	GENERATE_DID_FAIL(1044, "generate DID fail"),
	ENCRYPT_KEY_FAILED(1337, "encrypt key is failed"),
	SIGNATURE_FAILED(1338, "signature failed "),
	PRIVATE_KEY_ILLEGAL_FORMAT(1025, "private key illegal format"),
	CPT_NOT_EXIST(1060, "cpt not exist"),
	DID_NOT_EXIST(1041, "DID not exist"),
	CPT_AND_ISSUER_CANNOT_MATCH(1062, "cpt and issuer connot match"),
	
	QUERY_GRANT_ENCPY_KEY_FAILED(1501, "query grant resource encryption key failed "),
	DECRPTY_GRANT_KEY_FAILED(1502, "decrypt grant resource Key failed "),
	RESOURCE_NOT_EISTS(1503,"the resource do not exist"),
	RECOVERY_KEY_INCORRECT(1504,"recovery key pair is incorrect, can not reset DID auth"),
	PRK_PUK_NOT_MATCH(1505,"primary private key and public key do not match"),
	;
	
	  private Integer code;

	  private String message;

	  private ErrorMessage(Integer code, String message) {
	    this.code = code;
	    this.message = message;
	  }

	  public String getMessage() {
	    return message;
	  }
	  
	  public Integer getCode() {
		return code;
	  }

	  public static String getMessage(Integer code) {
	    for (ErrorMessage error : ErrorMessage.values()) {
	      if (error.code.equals(code)) {
	        return error.message;
	      }
	    }
	    return null;
	  }

	  public static String getMessage(ErrorMessage errorMessage) {
	    for (ErrorMessage error : ErrorMessage.values()) {
	      if (error.code.equals(errorMessage.code)) {
	        return error.message;
	      }
	    }
	    return null;
	  }
}
