package com.reddate.did.service;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.reddate.did.sdk.service.BaseService;

public class BaseServiceTest {
    @Test
    public void testConstructor() {
        BaseService actualBaseService = new BaseService("https://example.org/example", "ABC123", "myproject");

        assertEquals("myproject", actualBaseService.getProjectId());
        assertEquals("ABC123", actualBaseService.getToken());
        assertEquals("https://example.org/example", actualBaseService.getUrl());
    }
    
}

