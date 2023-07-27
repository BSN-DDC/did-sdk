package com.reddate.did.sdk.util;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author luoyb
 * Created on 2022/11/30
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class PairKey {
    private String priKey;
    private String pubKey;
}
