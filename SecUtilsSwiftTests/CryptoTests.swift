//
//  CryptoTests.swift
//  RSA_AES_Swift
//
//  Created by Ahmed Adouani on 27/02/2019.
//  Copyright © 2019 Ignacio Nieto Carvajal. All rights reserved.
//

import XCTest
@testable import SecUtilsSwift

class CryptoTests: XCTestCase {
    
    func testDecryptDataFrom8gwifiDotOrg() {
        //https://8gwifi.org/rsafunctions.jsp
        //use public key (pem)
        /*
         -----BEGIN PUBLIC KEY-----
         MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2XM6BM1msU3luXxlhq5+
         CYXpodyYsPyJqz04dMytKV4Ff7DvNeYgaa9MqBIL8HJ/OUNA+oRt0sxTsnEh3hxs
         frBRgq53+OiMxx6JzM/5Uo5gEdKd3W7NfQkqf5tWGUPZF67PtUrWtn8SEMom6Jhs
         BE7LWlqP6EwR0tMt1A1PrxSWSuUaoiWBA9pQYIIxLsl8GwfpNFkDvdnsGyylRe/t
         Z6cwhExmm21RtHWSSdjT5GC+Vw552VI/Ejmdv6kj7+AWbroSKRmNWoQ956tC+eQh
         iGq2UjATE8dXCFJZwOvLMJGmmy/ErcXkrL++33IR6u/MhfGtqJpqp9qoJxpt5p+l
         AQIDAQAB
         -----END PUBLIC KEY-----
         */
        let base64PrivateKey =  "MIIEogIBAAKCAQEA2XM6BM1msU3luXxlhq5+CYXpodyYsPyJqz04dMytKV4Ff7Dv"
            + "NeYgaa9MqBIL8HJ/OUNA+oRt0sxTsnEh3hxsfrBRgq53+OiMxx6JzM/5Uo5gEdKd"
            + "3W7NfQkqf5tWGUPZF67PtUrWtn8SEMom6JhsBE7LWlqP6EwR0tMt1A1PrxSWSuUa"
            + "oiWBA9pQYIIxLsl8GwfpNFkDvdnsGyylRe/tZ6cwhExmm21RtHWSSdjT5GC+Vw55"
            + "2VI/Ejmdv6kj7+AWbroSKRmNWoQ956tC+eQhiGq2UjATE8dXCFJZwOvLMJGmmy/E"
            + "rcXkrL++33IR6u/MhfGtqJpqp9qoJxpt5p+lAQIDAQABAoIBAGX0aNenlua7J2L4"
            + "uIGVfvLoHssNq2oQflwTsEzTSr2CoAFm7EHRTJFA6ChFjeOHS6+FoQnU3clglD2u"
            + "XbrOiPA9q3oiY44JOziBUQr+2F+k8dZpcitIsIBXs91w78WY0kkQZcMS++lFWysU"
            + "HXohPUQnzaDnpWG9iP3Yljw+oYXsu3dOweN602nX+jkHhZ0jd3NYPo1FSulcfOvg"
            + "Y9ZcmozNfVn6s2v3f3IMDRwvHihp7T16MFXt0d5Y0Vwj1+iRQq7fuwwdGZKXvzrq"
            + "majDNopSllUfufWqrd96oepo5o7E8l1EWr0/Qt8mhMndM1QeIyWqig+3Mjp57kPx"
            + "SQiL+YECgYEA+4F+sxEbJXavVfVUia9pKF6TV/C1cjye2mAdkaSxJyCZU+HXxR87"
            + "AWAqnSQOTqpufXrBw8qsdN720G6dP1rNWR4zFsoqIYlaFRGU0OCAHFICnCwZz/bV"
            + "10sagn6l2/0UqCQADa8BuzqkQPUYssJHWTIupzK8vO0ZWybGHdMU5wUCgYEA3VXx"
            + "5D+wY+kMjV87y5UpXq0x+A7jJnorwRT9wA/hH+i+uy5aIENjEplhBoqHlcJgcbgu"
            + "NDkvbB+Tt3sgHt0cgodcCzOLmYqBY2YaAbNPXWj77MNUL9+FTDOENZegotLiW7CD"
            + "9aHXJ+0QVB+EyKdYnFn6vw9qW+/XBbRJRjJs7s0CgYBNBV0trWFo2a3cXyMifytv"
            + "B3eMCNUoRNRJAAJOJedymhMakyEm5ueFBlRGh1IyWRM5LizErv6dU+K19goF6uLU"
            + "FeGDayn31z5VEWtHhFj3U04lUYQeIfNe2UsnB233rstyqoOxrRSUp+LBWc3UgJal"
            + "BC8xWOJf4SRQu9EUNR5DmQKBgDEBDFNKvpUATiUmxqhmWAh8NCoFsckdF37iVOQn"
            + "H+LetwveUVn/UXoWt2KpXSeNJ6lF7ATn/FXmD+B5xDzRG7TSn1Bjky7leYw2WN+z"
            + "gYje65gaDxOiW3LpnQX4kjo6kp9WT4Ec2fQfCpR1fgKm+nlzeo6+rP+59FNw/SAr"
            + "ne6pAoGAfwQf8cUT5D9tPx9L0wbW3YswkWoTLhvWmP5jUiwRKFY20dzyfBgzL58B"
            + "YZvmTXvfe15VMzLv35MchJH+wiWXCOOw1cG/t2fZo/dPHBKS4DpLAt6/4s0MXN2q"
            + "pyHybH4Y5Zz5CIQnIEPUxBDZrUfiXMKGokRajJvgeQ+1hx4S4Zg="
        
        let privateKey = SecKey.privateKey(from: base64PrivateKey)!
        
        let website_encrypted = "X9F248dgK8bqV9KGxFOdMi1Og+eVIZLJVsUTnUKF/3zPfV5jsMzVhqcq7z+XalSEGAkDLkEwuXCcRZN1LJsu5QFsiKfHhV1eqsKKbxWaLko7EuT59EKoanmUD0VhGSlkcF6Fu2Sl0PSJ7eFIg+cSEr5qvFKxFZ9eadMvynu/n95Dds3zJzmYPYnQBbWh1WHA0zJSZBAySr/yPxsLErDrkcDzyWjyffHQyYmNb/W7TgPZgCqINkzeX6xj2YVWCVqHfdomxIphL+DAtajkVWuxBdSlyW3+dCw5dTOngnXwoUejwZ9DazBh6vw1oyEoJ9wC0n2hafqxqIOP1t4X/mnklQ=="
        let crypto = SURsaCrypto()
        let decryptedphpData = crypto.decrypt(encryptedString: website_encrypted, privateKey: privateKey)
        let encryptedString = String(data: decryptedphpData!, encoding: .utf8)!
        XCTAssertEqual("ddd", encryptedString)
    }
    
    func testDecryptDataFromPhp() {
        //use public key (pem)
        /*
         -----BEGIN PUBLIC KEY-----
         MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2XM6BM1msU3luXxlhq5+
         CYXpodyYsPyJqz04dMytKV4Ff7DvNeYgaa9MqBIL8HJ/OUNA+oRt0sxTsnEh3hxs
         frBRgq53+OiMxx6JzM/5Uo5gEdKd3W7NfQkqf5tWGUPZF67PtUrWtn8SEMom6Jhs
         BE7LWlqP6EwR0tMt1A1PrxSWSuUaoiWBA9pQYIIxLsl8GwfpNFkDvdnsGyylRe/t
         Z6cwhExmm21RtHWSSdjT5GC+Vw552VI/Ejmdv6kj7+AWbroSKRmNWoQ956tC+eQh
         iGq2UjATE8dXCFJZwOvLMJGmmy/ErcXkrL++33IR6u/MhfGtqJpqp9qoJxpt5p+l
         AQIDAQAB
         -----END PUBLIC KEY-----
         */
        let base64PrivateKey =  "MIIEogIBAAKCAQEA2XM6BM1msU3luXxlhq5+CYXpodyYsPyJqz04dMytKV4Ff7Dv"
            + "NeYgaa9MqBIL8HJ/OUNA+oRt0sxTsnEh3hxsfrBRgq53+OiMxx6JzM/5Uo5gEdKd"
            + "3W7NfQkqf5tWGUPZF67PtUrWtn8SEMom6JhsBE7LWlqP6EwR0tMt1A1PrxSWSuUa"
            + "oiWBA9pQYIIxLsl8GwfpNFkDvdnsGyylRe/tZ6cwhExmm21RtHWSSdjT5GC+Vw55"
            + "2VI/Ejmdv6kj7+AWbroSKRmNWoQ956tC+eQhiGq2UjATE8dXCFJZwOvLMJGmmy/E"
            + "rcXkrL++33IR6u/MhfGtqJpqp9qoJxpt5p+lAQIDAQABAoIBAGX0aNenlua7J2L4"
            + "uIGVfvLoHssNq2oQflwTsEzTSr2CoAFm7EHRTJFA6ChFjeOHS6+FoQnU3clglD2u"
            + "XbrOiPA9q3oiY44JOziBUQr+2F+k8dZpcitIsIBXs91w78WY0kkQZcMS++lFWysU"
            + "HXohPUQnzaDnpWG9iP3Yljw+oYXsu3dOweN602nX+jkHhZ0jd3NYPo1FSulcfOvg"
            + "Y9ZcmozNfVn6s2v3f3IMDRwvHihp7T16MFXt0d5Y0Vwj1+iRQq7fuwwdGZKXvzrq"
            + "majDNopSllUfufWqrd96oepo5o7E8l1EWr0/Qt8mhMndM1QeIyWqig+3Mjp57kPx"
            + "SQiL+YECgYEA+4F+sxEbJXavVfVUia9pKF6TV/C1cjye2mAdkaSxJyCZU+HXxR87"
            + "AWAqnSQOTqpufXrBw8qsdN720G6dP1rNWR4zFsoqIYlaFRGU0OCAHFICnCwZz/bV"
            + "10sagn6l2/0UqCQADa8BuzqkQPUYssJHWTIupzK8vO0ZWybGHdMU5wUCgYEA3VXx"
            + "5D+wY+kMjV87y5UpXq0x+A7jJnorwRT9wA/hH+i+uy5aIENjEplhBoqHlcJgcbgu"
            + "NDkvbB+Tt3sgHt0cgodcCzOLmYqBY2YaAbNPXWj77MNUL9+FTDOENZegotLiW7CD"
            + "9aHXJ+0QVB+EyKdYnFn6vw9qW+/XBbRJRjJs7s0CgYBNBV0trWFo2a3cXyMifytv"
            + "B3eMCNUoRNRJAAJOJedymhMakyEm5ueFBlRGh1IyWRM5LizErv6dU+K19goF6uLU"
            + "FeGDayn31z5VEWtHhFj3U04lUYQeIfNe2UsnB233rstyqoOxrRSUp+LBWc3UgJal"
            + "BC8xWOJf4SRQu9EUNR5DmQKBgDEBDFNKvpUATiUmxqhmWAh8NCoFsckdF37iVOQn"
            + "H+LetwveUVn/UXoWt2KpXSeNJ6lF7ATn/FXmD+B5xDzRG7TSn1Bjky7leYw2WN+z"
            + "gYje65gaDxOiW3LpnQX4kjo6kp9WT4Ec2fQfCpR1fgKm+nlzeo6+rP+59FNw/SAr"
            + "ne6pAoGAfwQf8cUT5D9tPx9L0wbW3YswkWoTLhvWmP5jUiwRKFY20dzyfBgzL58B"
            + "YZvmTXvfe15VMzLv35MchJH+wiWXCOOw1cG/t2fZo/dPHBKS4DpLAt6/4s0MXN2q"
            + "pyHybH4Y5Zz5CIQnIEPUxBDZrUfiXMKGokRajJvgeQ+1hx4S4Zg="
        
        let privateKey = SecKey.privateKey(from: base64PrivateKey)!
        
        let php_encrypted = "a6yTGjgq8PbENvsiWhlllldpjBeK0Vgd9FyGo8cl5wrRhHaUUODFme7HFWStfK6ZuZizMG77seNABUH/nN8AgDg85cF+FrbF1oTz077sMHR4XXbR0jnry3nHDKNvNrz88U5mJph5qiMAfvDfDpIboiPXszVE1JR6GNW/o0OHC0Cj1fd9OjP9WgysQbyXezVzFnTZDIsun8Z1oYUy5iIbJhUBDLMx0uYh8O2Vn82LM3EvcxbUWt5Pr3yJy0Jzx5Is0AmoSGVcUshyqzEGbH4bLcJvoSkXkzhQJArBAVrd9Z/JrYeiKKzl1bhHN419Sd0WOnPyQSnL/+xSy1fsd97/ow=="
        let crypto = SURsaCrypto()
        let decryptedphpData = crypto.decrypt(encryptedString: php_encrypted, privateKey: privateKey)
        let encryptedString = String(data: decryptedphpData!, encoding: .utf8)!
        XCTAssertEqual("Hello World", encryptedString)
    }
    
    func testGettingKeysFromOPENSSLStrings() {
        //http://krisjordan.com/essays/encrypting-with-rsa-key-pairs
        let base64PrivateKey =  "MIIEogIBAAKCAQEA2XM6BM1msU3luXxlhq5+CYXpodyYsPyJqz04dMytKV4Ff7Dv"
        + "NeYgaa9MqBIL8HJ/OUNA+oRt0sxTsnEh3hxsfrBRgq53+OiMxx6JzM/5Uo5gEdKd"
        + "3W7NfQkqf5tWGUPZF67PtUrWtn8SEMom6JhsBE7LWlqP6EwR0tMt1A1PrxSWSuUa"
        + "oiWBA9pQYIIxLsl8GwfpNFkDvdnsGyylRe/tZ6cwhExmm21RtHWSSdjT5GC+Vw55"
        + "2VI/Ejmdv6kj7+AWbroSKRmNWoQ956tC+eQhiGq2UjATE8dXCFJZwOvLMJGmmy/E"
        + "rcXkrL++33IR6u/MhfGtqJpqp9qoJxpt5p+lAQIDAQABAoIBAGX0aNenlua7J2L4"
        + "uIGVfvLoHssNq2oQflwTsEzTSr2CoAFm7EHRTJFA6ChFjeOHS6+FoQnU3clglD2u"
        + "XbrOiPA9q3oiY44JOziBUQr+2F+k8dZpcitIsIBXs91w78WY0kkQZcMS++lFWysU"
        + "HXohPUQnzaDnpWG9iP3Yljw+oYXsu3dOweN602nX+jkHhZ0jd3NYPo1FSulcfOvg"
        + "Y9ZcmozNfVn6s2v3f3IMDRwvHihp7T16MFXt0d5Y0Vwj1+iRQq7fuwwdGZKXvzrq"
        + "majDNopSllUfufWqrd96oepo5o7E8l1EWr0/Qt8mhMndM1QeIyWqig+3Mjp57kPx"
        + "SQiL+YECgYEA+4F+sxEbJXavVfVUia9pKF6TV/C1cjye2mAdkaSxJyCZU+HXxR87"
        + "AWAqnSQOTqpufXrBw8qsdN720G6dP1rNWR4zFsoqIYlaFRGU0OCAHFICnCwZz/bV"
        + "10sagn6l2/0UqCQADa8BuzqkQPUYssJHWTIupzK8vO0ZWybGHdMU5wUCgYEA3VXx"
        + "5D+wY+kMjV87y5UpXq0x+A7jJnorwRT9wA/hH+i+uy5aIENjEplhBoqHlcJgcbgu"
        + "NDkvbB+Tt3sgHt0cgodcCzOLmYqBY2YaAbNPXWj77MNUL9+FTDOENZegotLiW7CD"
        + "9aHXJ+0QVB+EyKdYnFn6vw9qW+/XBbRJRjJs7s0CgYBNBV0trWFo2a3cXyMifytv"
        + "B3eMCNUoRNRJAAJOJedymhMakyEm5ueFBlRGh1IyWRM5LizErv6dU+K19goF6uLU"
        + "FeGDayn31z5VEWtHhFj3U04lUYQeIfNe2UsnB233rstyqoOxrRSUp+LBWc3UgJal"
        + "BC8xWOJf4SRQu9EUNR5DmQKBgDEBDFNKvpUATiUmxqhmWAh8NCoFsckdF37iVOQn"
        + "H+LetwveUVn/UXoWt2KpXSeNJ6lF7ATn/FXmD+B5xDzRG7TSn1Bjky7leYw2WN+z"
        + "gYje65gaDxOiW3LpnQX4kjo6kp9WT4Ec2fQfCpR1fgKm+nlzeo6+rP+59FNw/SAr"
        + "ne6pAoGAfwQf8cUT5D9tPx9L0wbW3YswkWoTLhvWmP5jUiwRKFY20dzyfBgzL58B"
        + "YZvmTXvfe15VMzLv35MchJH+wiWXCOOw1cG/t2fZo/dPHBKS4DpLAt6/4s0MXN2q"
        + "pyHybH4Y5Zz5CIQnIEPUxBDZrUfiXMKGokRajJvgeQ+1hx4S4Zg="
        
        let base64PublicKey =  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2XM6BM1msU3luXxlhq5+"
        + "CYXpodyYsPyJqz04dMytKV4Ff7DvNeYgaa9MqBIL8HJ/OUNA+oRt0sxTsnEh3hxs"
        + "frBRgq53+OiMxx6JzM/5Uo5gEdKd3W7NfQkqf5tWGUPZF67PtUrWtn8SEMom6Jhs"
        + "BE7LWlqP6EwR0tMt1A1PrxSWSuUaoiWBA9pQYIIxLsl8GwfpNFkDvdnsGyylRe/t"
        + "Z6cwhExmm21RtHWSSdjT5GC+Vw552VI/Ejmdv6kj7+AWbroSKRmNWoQ956tC+eQh"
        + "iGq2UjATE8dXCFJZwOvLMJGmmy/ErcXkrL++33IR6u/MhfGtqJpqp9qoJxpt5p+l"
        + "AQIDAQAB"
        
        let privateKey = SecKey.privateKey(from: base64PrivateKey)!
        let publicKey = SecKey.publicKey(from: base64PublicKey)!
        
        let pubKeyData = publicKey.data()!
        
        let keyType = kSecAttrKeyTypeRSA as String
        let keySize = 2048
        let exportImportManager = SUCryptoKeysManager()
        if let exportableDERKey = exportImportManager.exportPublicKeyToDER(pubKeyData, keyType: keyType, keySize: keySize) {
            print("Exportable key in DER format:\n\(exportableDERKey.hexDescription)\n")
            let exportablePEMKey = exportImportManager.PEMKeyFromDERKey(exportableDERKey)
            print("Exportable key in PEM format:\n\(exportablePEMKey)\n")
        } else {
            XCTAssert(false)
        }
        
        let crypto = SURsaCrypto()
        let string = "sample text to be encrypted and decrypted"
        
        let signature = crypto.signString(string: string, privateKey: privateKey)
        
        XCTAssertEqual("bnULm3P8zC8pTxy7Y+B8xTmPvcxy4W6t0qS/NSadcGJIVta3w+vHb8e3UuRY8FJlS0FU3qF3+VaKE7f1zWzW3HPJriXh0IoHguqeJLQ815xL/nhrAefgXVusxnniFH1CG+vwkPcAcDJXrAwiuUmZFi55Va/hzt1TtF93uzblJ9Qj318wGceat44d3pmx4hKYU1xFjgRVXHfQWhLIS+OS3sA3VFV9GoqVOg4MnbOC0F+IpkscI37fJJwSvoA8Zzo7EUy/D7m23BZJfRq+GjcqsecjUBIBE2uoUtxltCtwhKXfX25nuca89Ogt/FlkOTYHSC1x9XLZpBOvf/UbOqvhHA==", signature)
        let result: Bool = crypto.verifyString(string: string, signature: signature!, publicKey: publicKey)
        XCTAssert(result)
        
        /*let encrypted = crypto.encryptString(string: string, publicKey: publicKey)
         XCTAssertEqual("NkItueRsh4RoaAGCoKWZo5zaGpH0m9k4j8IhIXmh5DFSma4AUsLDrXjOq5rRu+1gKqnVhBU/HB+uQ72NpRlynzOUbEooGwCCdrEgfj9EBBqLQaMoMmejAkdm+ki2kDtnkrSHgZQQSekJbIckSWGnOexMcSi7ug35ttFCG4bUnjRymGrwcnWf4vcQ8OPEaN3CNUnWl9/L/XcBFNvzzcPg6XPCpZFWO4dKTU8SRh/8hzGBsmp+CStbEO1J3cc4mhVacxfsAVN/sylFycxhCKnf8M2j0m4qyrdA/HWk9uOpfkvHuGfyyz1PNEnt3zdDZPW301D13ZcQr89sHcPA9gO1eA==", encrypted)*/
    }
    
    
    func testGettingKeysFromStrings() {
        let base64PrivateKey =  "MIIEogIBAAKCAQEAnbDwQVjcHrjSEtg0nk5DRgbwrGMq8rdO4lHWUncnlbMn7nhTjggBs0ZPyNu9IhmuW4xgAQ6rl5HzYX1qzrwEUoMriYs86o/bYYmehknr0wyEvDCQ/Adl9epYWj40zhIrpxAoMbx/iyPwqLFylDZC0j5AK6vYADu4fCaOkioXuW2qczC/Wjhca1QUgkMOKTIAUu0aUx5RkmcDAJKZhSnyquDEaQRykPdTrSZFDxZxAIEZ16hLgKeXfnReCDFChdHUzdBZHAsrmvEIWcS0L2+QP5Uct7mp5QgoRvzhvT32SGqr3Xf9YgxXuP1siQQv9fTjdB7wBNKbAYfPiLbICXK3BQIDAQABAoIBAAdV5HdFvkeiQAjRt0Y99xyE1Mv6zlP9eaqcNU90wjSmjDmoWKAHeKdxoo3XcFRBGZP3UxKkL2XyS34XgCZ0fJxSBG52ObPiU/Q/m049QL56m0TIhZYTygcciwD3r9Z+Ozr0TMpeLcNikp67p8wukgExwCPH71kOGNDoV5guY8LOZ9LDMODvqxzn6042CHX6unpiK4BNTc3ULM/IoNAV6831ulgdRu+RAP9iDEIoV7t/mlwCKqY6cawUsCtbVFu2rJRyHC6+Pat5lpc6hKrAfZz+6xBVlKyY4C6o3zjBFfmUUMfyb2zvx30NFfxGy4h9R1l4yRusVxLxXbsgaE3oYMECgYEAzYoeMqnn70phcOqKJXMWZQYqVilSn318ywlNxaTeYvMuBQ7/eE3EfaJK8aHaGhsVMm4tzhqUTeR3dHs074KRioN5zLu03rDaIL0UAo6YLaOPY//sfVZdscTrFRcISzhkKEl8JoHQYVvaCQsFMwCxjwQ2bmPy/5beRN/5KoZo8rkCgYEAxGedospa8lCOhxZoBDJlr86xlwDOX7Hi/9IWtJQ2L5vNl7sCichFGC3eb1gGRXGKiZCe7x5UAnY98OFkBkmWln+EkVfK36nxHLmmrpxSWCDR7zGsZYffv0QfTP0Q4jQqJLmALLDw9+rjpsdSP1r3xPOQSbiZgy5j2FGt0g0kMK0CgYBs5kf3qePT+cHE1M9a5i4wWmLmAcDf9dm/rW9CT4bwQE3aqkaa1AFOW0V/3rQy7rR9YrjsIVMALhNIaNr0J2a7T8uhuLYs4uC/Rc6rSCfCzozze64t/itoO6AeLXTcfcU7PywDLvZcDxFnhyo7CpwI3T+Fn3kpCCM9tLlMWaiTKQKBgCyLk6UoYBg1TR42ZsEM7SNCreShuizaG7IJ5DxwoRmLLMYNFDZLxeAGBz0ZqdJ2PgWVV3bEWil0x/eqJxWF+zGHGnocf1bbJGRvdu6DZem3B+ZITeF5P7YRrUe43etwCV7q87cvKngQPjHFY1IbP7bbxw3xYF/wVZTqcZICiQLBAoGAf9V70fzjaiiK5Dd0VyEhuugBr2+GO79wJlQffJ5re16ORW2h4VakX3Ala5Z48N2FkuCbZHyb8gPI9zgZFBb2zJprg/0ZnZ9CGweyu8MoBJ0B2Dd3wV5dwvjHWyTuDoJwSjFeW3Wn375D37vDD2+CGHhI4WyXdWpE7MZWQY3ClI8="
        let base64PublicKey =  "MIIBCgKCAQEAnbDwQVjcHrjSEtg0nk5DRgbwrGMq8rdO4lHWUncnlbMn7nhTjggBs0ZPyNu9IhmuW4xgAQ6rl5HzYX1qzrwEUoMriYs86o/bYYmehknr0wyEvDCQ/Adl9epYWj40zhIrpxAoMbx/iyPwqLFylDZC0j5AK6vYADu4fCaOkioXuW2qczC/Wjhca1QUgkMOKTIAUu0aUx5RkmcDAJKZhSnyquDEaQRykPdTrSZFDxZxAIEZ16hLgKeXfnReCDFChdHUzdBZHAsrmvEIWcS0L2+QP5Uct7mp5QgoRvzhvT32SGqr3Xf9YgxXuP1siQQv9fTjdB7wBNKbAYfPiLbICXK3BQIDAQAB"
        
        let privateKey = SecKey.privateKey(from: base64PrivateKey)!
        let publicKey = SecKey.publicKey(from: base64PublicKey)!
       
        let pubKeyData = publicKey.data()!
        
        let keyType = kSecAttrKeyTypeRSA as String
        let keySize = 2048
        let exportImportManager = SUCryptoKeysManager()
        if let exportableDERKey = exportImportManager.exportPublicKeyToDER(pubKeyData, keyType: keyType, keySize: keySize) {
            print("Exportable key in DER format:\n\(exportableDERKey.hexDescription)\n")
            let exportablePEMKey = exportImportManager.PEMKeyFromDERKey(exportableDERKey)
            print("Exportable key in PEM format:\n\(exportablePEMKey)\n")
        } else {
            XCTAssert(false)
        }
        
        let crypto = SURsaCrypto()
        let string = "sample text to be encrypted and decrypted"
        
        let signature = crypto.signString(string: string, privateKey: privateKey)
        
        XCTAssertEqual("ZTAkhhveAez7cbpu8z+5/8tkqsYLpwNuZZd8C6y1/fWdZOLRGFlc/BYEV5DGFlLXh/009bb4dHiEh8sSl0wLhnF0GjEbbpnMH29qiJNL8HnBV8DPHdjzvywy0qizUh4c4I451RGf/phc/QOMajI+D1toyInbjM33RfCNClgHUVCgpgSssqkHAo4DKQ4BCH8NgDI218clw/SAAb8SLoHPNq+JyTTQF233E0WSjKiBHhsbIIIE+dZOCgN98hr/URx20dT1rBVk6Vf8tocyyXQfcuZu8xczhpAtSkNk89bHlev0N0ij+ZplHyN7NUb7ltEb9FhO3cVdI1eMAQ3FH+WZrQ==", signature)
        let result: Bool = crypto.verifyString(string: string, signature: signature!, publicKey: publicKey)
        XCTAssert(result)
        
        /*let encrypted = crypto.encryptString(string: string, publicKey: publicKey)
        XCTAssertEqual("NkItueRsh4RoaAGCoKWZo5zaGpH0m9k4j8IhIXmh5DFSma4AUsLDrXjOq5rRu+1gKqnVhBU/HB+uQ72NpRlynzOUbEooGwCCdrEgfj9EBBqLQaMoMmejAkdm+ki2kDtnkrSHgZQQSekJbIckSWGnOexMcSi7ug35ttFCG4bUnjRymGrwcnWf4vcQ8OPEaN3CNUnWl9/L/XcBFNvzzcPg6XPCpZFWO4dKTU8SRh/8hzGBsmp+CStbEO1J3cc4mhVacxfsAVN/sylFycxhCKnf8M2j0m4qyrdA/HWk9uOpfkvHuGfyyz1PNEnt3zdDZPW301D13ZcQr89sHcPA9gO1eA==", encrypted)*/
    }
    
    
    func testSigningString() {
        let keygen = SUKeychain(service: "APP")
        let crypto = SURsaCrypto()
        let string = "sample text to be encrypted and decrypted"
        let keyPair: (publicKey: SecKey?, privateKey: SecKey?) = keygen.generateRsaKeyPair()
        let privateKey = keyPair.privateKey!
        let base64PrivateKey = privateKey.base64Key()!
        let base64PublicKey = keyPair.publicKey!.base64Key()!
        print("base64PrivateKey: \(base64PrivateKey)")
        print("base64PublicKey: \(base64PublicKey)")
        let signature = crypto.signString(string: string, privateKey: SecKey.privateKey(from: base64PrivateKey)!)
        let result: Bool = crypto.verifyString(string: string, signature: signature!, publicKey: keyPair.publicKey!)
        XCTAssert(result)
    }
    
    func testSigningData() {
        let keygen = SUKeychain(service: "APP")
        let crypto = SURsaCrypto()
        let string = "sample text to be encrypted and decrypted"
        let keyPair: (publicKey: SecKey?, privateKey: SecKey?) = keygen.generateRsaKeyPair()
        let data = string.data(using: .utf8)
        let signature = crypto.sign(data: data!, privateKey: keyPair.privateKey!)
        let result = crypto.verify(data: data!, signature: signature!, publicKey: keyPair.publicKey!)
        XCTAssert(result)
    }
    
    func testEncryptingString() {
        let keygen = SUKeychain(service: "APP")
        let crypto = SURsaCrypto()
        let string = "sample text to be encrypted and decrypted"
        let keyPair: (publicKey: SecKey?, privateKey: SecKey?) = keygen.generateRsaKeyPair()
        let encrypted = crypto.encryptString(string: string, publicKey: keyPair.publicKey!)
        let plaintext = crypto.decryptString(encryptedString: encrypted!, privateKey: keyPair.privateKey!)
        XCTAssertEqual(string, plaintext)
    }
    
    func testEncryptingData() {
        let keygen = SUKeychain(service: "APP")
        let crypto = SURsaCrypto()
        let string: String = "sample text to be encrypted and decrypted"
        let keyPair: (publicKey: SecKey?, privateKey: SecKey?) = keygen.generateRsaKeyPair()
        let data = string.data(using: .utf8)!
        let encrypted = crypto.encrypt(data: data, publicKey: keyPair.publicKey!)
        let plainData = crypto.decrypt(encryptedString: encrypted!, privateKey: keyPair.privateKey!)
        let plaintext = String(data: plainData!, encoding: .utf8)
        XCTAssertEqual(string, plaintext)
    }
    
    func testGenerationKeyPair() {
        let keygen = SUKeychain(service: "APP")
        let keyPair: (publicKey: SecKey?, privateKey: SecKey?) = keygen.generateRsaKeyPair()
        let publicKey = keyPair.publicKey
        let privateKey = keyPair.privateKey
        
        //Encrypt a string with the public key
        let string: String = "sample text to be encrypted and decrypted"
        let blockSize = SecKeyGetBlockSize(publicKey!)
        var messageEncrypted = [UInt8](repeating: 0, count: blockSize)
        var messageEncryptedSize = blockSize
        
        var status: OSStatus!
        
        status = SecKeyEncrypt(publicKey!, SecPadding.PKCS1, string, string.count, &messageEncrypted, &messageEncryptedSize)
        
        XCTAssert(status == noErr)
        
        //Decrypt the entrypted string with the private key
        var messageDecrypted = [UInt8](repeating: 0, count: blockSize)
        var messageDecryptedSize = messageEncryptedSize
        
        status = SecKeyDecrypt(privateKey!, SecPadding.PKCS1, &messageEncrypted, messageEncryptedSize, &messageDecrypted, &messageDecryptedSize)
        
        XCTAssert(status == noErr)
        
        XCTAssertEqual(string, NSString(bytes: &messageDecrypted, length: messageDecryptedSize, encoding: String.Encoding.utf8.rawValue)! as String)
        

    }
}
