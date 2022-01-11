package com.reddate.did.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;

import com.reddate.did.sdk.exception.DidException;
import com.reddate.did.sdk.param.req.ResetDidAuth;
import com.reddate.did.sdk.param.req.ResetDidAuthKey;
import com.reddate.did.sdk.param.resp.DidDataWrapper;
import com.reddate.did.sdk.param.resp.DocumentInfo;
import com.reddate.did.sdk.protocol.common.KeyPair;
import com.reddate.did.sdk.protocol.response.ResultData;
import com.reddate.did.sdk.service.DidService;

public class DidServiceTest {
    @Test
    public void testConstructor() {
        DidService actualDidService = new DidService("https://example.org/example", "ABC123", "myproject");

        assertEquals("myproject", actualDidService.getProjectId());
        assertEquals("https://example.org/example", actualDidService.getUrl());
        assertEquals("ABC123", actualDidService.getToken());
    }

    @Test
    public void testGenerateDid() {
        assertThrows(RuntimeException.class,
                () -> (new DidService("https://example.org/example", "ABC123", "myproject")).generateDid(true));
        assertThrows(RuntimeException.class, () -> (new DidService("UUU/UUU", "ABC123", "myproject")).generateDid(true));
        assertThrows(RuntimeException.class,
                () -> (new DidService("https://w3id.org/did/v1", "ABC123", "myproject")).generateDid(true));
    }

    @Test
    public void testGenerateDid2() {
        ResultData<DidDataWrapper> actualGenerateDidResult = (new DidService("https://example.org/example", "ABC123",
                "myproject")).generateDid(false);
        assertEquals(200, actualGenerateDidResult.getCode().intValue());
        assertEquals("success", actualGenerateDidResult.getMsg());
        DidDataWrapper data = actualGenerateDidResult.getData();
        DocumentInfo document = data.getDocument();
        assertEquals("1", document.getVersion());
        assertEquals("Secp256k1", data.getAuthKeyInfo().getType());
        assertEquals("Secp256k1", data.getRecyKeyInfo().getType());
        assertEquals("Secp256k1", document.getProof().getType());
        assertEquals("Secp256k1", document.getAuthentication().getType());
        assertEquals("Secp256k1", document.getRecovery().getType());
    }

   

   

    
    

   
    @Test
    public void testResetDidAuth() throws Exception {
        DidService didService = new DidService("https://example.org/example", "ABC123", "myproject");

        ResetDidAuthKey resetDidAuthKey = new ResetDidAuthKey();
        resetDidAuthKey.setPublicKey("Public Key");
        resetDidAuthKey.setPrivateKey("Private Key");
        resetDidAuthKey.setType("Type");

        KeyPair keyPair = new KeyPair();
        keyPair.setPublicKey("Public Key");
        keyPair.setPrivateKey("Private Key");
        keyPair.setType("Type");

        ResetDidAuth resetDidAuth = new ResetDidAuth();
        //resetDidAuth.setRecoveryKey(resetDidAuthKey);
        resetDidAuth.setPrimaryKeyPair(keyPair);
        resetDidAuth.setDid("Did");
        assertThrows(DidException.class, () -> didService.resetDidAuth(resetDidAuth));
    }

    @Test
    public void testResetDidAuth2() throws Exception {
        DidService didService = new DidService("\"", "ABC123", "myproject");

        ResetDidAuthKey resetDidAuthKey = new ResetDidAuthKey();
        resetDidAuthKey.setPublicKey("Public Key");
        resetDidAuthKey.setPrivateKey("Private Key");
        resetDidAuthKey.setType("Type");

        KeyPair keyPair = new KeyPair();
        keyPair.setPublicKey("Public Key");
        keyPair.setPrivateKey("Private Key");
        keyPair.setType("Type");

        ResetDidAuth resetDidAuth = new ResetDidAuth();
        //resetDidAuth.setRecoveryKey(resetDidAuthKey);
        resetDidAuth.setPrimaryKeyPair(keyPair);
        resetDidAuth.setDid("Did");
        assertThrows(DidException.class, () -> didService.resetDidAuth(resetDidAuth));
    }
    
}

