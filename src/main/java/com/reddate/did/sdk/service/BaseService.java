package com.reddate.did.sdk.service;

import java.util.List;
import java.util.Map;

/**
 * 
 * the did service implement base class,
 *  some common function write in this class
 * 
 * 
 * @author danny
 *
 */
public class BaseService {

	private String url;
	
	private String token;
	
	private String projectId;
	
	public BaseService(String url, String projectId,String token) {
		super();
		this.url = url;
		this.token = token;
		this.projectId = projectId;
	}

	public String getToken() {
		return token;
	}

	public String getProjectId() {
		return projectId;
	}

	public String getUrl() {
		return url;
	}
	
}
