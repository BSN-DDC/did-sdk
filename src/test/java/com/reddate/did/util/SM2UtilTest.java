package com.reddate.did.util;

import com.reddate.did.sdk.util.PairKey;
import com.reddate.did.sdk.util.SM2Util;
import org.junit.Test;

public class SM2UtilTest {

    @Test
    public void getSm2Keys() {
        //DID公私钥对、交互公私钥对生成
        PairKey sm2Keys = SM2Util.getSm2Keys(false);
        System.out.println("DID公钥："+sm2Keys.getPubKey());
        System.out.println("DID私钥："+sm2Keys.getPriKey());
    }
}