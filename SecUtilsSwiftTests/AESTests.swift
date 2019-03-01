//
//  CryptoManagerTests.swift
//  CryptoManagerTests
//
//  Created by Ahmed Adouani on 25/02/2019.
//  Copyright © 2019 Ignacio Nieto Carvajal. All rights reserved.
//

import XCTest
@testable import SecUtilsSwift


class AESTests: XCTestCase {

    func testAESExample() {
        do {
            let digest = "hello world".data(using: .utf8)!
            let password = "foo"
            let salt = SUAesCbcCrypto.randomSalt()
            let iv = SUAesCbcCrypto.randomIv()
            let key = try SUAesCbcCrypto.createKey(password: password.data(using: .utf8)!, salt: salt)
            let aes = try SUAesCbcCrypto(key: key, iv: iv)
            let encrypted = try aes.encrypt(digest)
            let decrypted = try aes.decrypt(encrypted)
            
            print("Encrypted: \(encrypted.hexDescription)")
            print("Decrypted: \(decrypted.hexDescription)")
            print("Password: \(password)")
            print("Key: \(key.hexDescription)")
            print("IV: \(iv.hexDescription)")
            print("Salt: \(salt.hexDescription)")
            print(" ")
            
            print("#! /bin/sh")
            print("echo \(digest.hexDescription) | xxd -r -p > digest.txt")
            print("echo \(encrypted.hexDescription) | xxd -r -p > encrypted.txt")
            print("openssl aes-256-cbc -K \(key.hexDescription) -iv \(iv.hexDescription) -e -in digest.txt -out encrypted-openssl.txt")
            print("openssl aes-256-cbc -K \(key.hexDescription) -iv \(iv.hexDescription) -d -in encrypted.txt -out decrypted-openssl.txt")
        } catch {
            print("Failed")
            print(error)
            XCTAssert(false)
        }
    }
    //KeyTransRecipientInfo AES with RSA CMS
    func testAdvancedExample() {
        do {
            let digest = "hello world".data(using: .utf8)!
            let password = "foo"
            let salt = SUAesCbcCrypto.randomSalt()
            let iv = SUAesCbcCrypto.randomIv()
            let key = try SUAesCbcCrypto.createKey(password: password.data(using: .utf8)!, salt: salt)
            let aes = try SUAesCbcCrypto(key: key, iv: iv)
            let encrypted = try aes.encrypt(digest)
            let decrypted = try aes.decrypt(encrypted)
            
            print("Encrypted: \(encrypted.hexDescription)")
            print("Decrypted: \(decrypted.hexDescription)")
            print("Password: \(password)")
            print("Key: \(key.hexDescription)")
            print("IV: \(iv.hexDescription)")
            print("Salt: \(salt.hexDescription)")
            print(" ")
            
            print("#! /bin/sh")
            print("echo \(digest.hexDescription) | xxd -r -p > digest.txt")
            print("echo \(encrypted.hexDescription) | xxd -r -p > encrypted.txt")
            print("openssl aes-256-cbc -K \(key.hexDescription) -iv \(iv.hexDescription) -e -in digest.txt -out encrypted-openssl.txt")
            print("openssl aes-256-cbc -K \(key.hexDescription) -iv \(iv.hexDescription) -d -in encrypted.txt -out decrypted-openssl.txt")
        } catch {
            print("Failed")
            print(error)
            XCTAssert(false)
        }
    }
    
    func testEncryptionDecryptionWithStoreIVAndKey() {
        let ivBase64 = "hKEDRK1arWFs7sV1vu+IbQ=="
        let keyBase64 = "4WWK/GNbRiODxbspp0Z+uoLVE7IA2g76wpu+pX3LCmI="
        let key = Data(base64Encoded: keyBase64)!
        let iv = Data(base64Encoded: ivBase64)!
        
        let digest = "hello world".data(using: .utf8)!
        
        let aes = try! SUAesCbcCrypto(key: key, iv: iv)
        let encrypted = try! aes.encrypt(digest)
        let decrypted = try! aes.decrypt(encrypted)
        
        let decryptedString = String(data: decrypted, encoding: .utf8)
        XCTAssertEqual("hello world", decryptedString)
        
    }
    
    func testDecryptionFromAWebsiteExample() {
        //https://www.cryptool.org/en/cto-highlights/aes
        
        let key = "e1658afc635b462383c5bb29a7467eba82d513b200da0efac29bbea57dcb0a62".hexadecimal!
        let iv = "84a10344ad5aad616ceec575beef886d".hexadecimal!
        
        let aes = try! SUAesCbcCrypto(key: key, iv: iv)
        let encrypted = "50d3274d4468ed33e69ab6ef8a02a046".hexadecimal!
        let decrypted = try! aes.decrypt(encrypted)
        
        let decryptedString = String(data: decrypted, encoding: .utf8)
        XCTAssertEqual("Hello World", decryptedString)
        
    }
    
}
