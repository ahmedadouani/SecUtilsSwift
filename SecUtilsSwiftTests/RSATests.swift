//
//  RSATests.swift
//  RSA_AES_SwiftTests
//
//  Created by Ahmed Adouani on 27/02/2019.
//  Copyright © 2019 Ignacio Nieto Carvajal. All rights reserved.
//

import XCTest
@testable import SecUtilsSwift

class RSATests: XCTestCase {

    override func setUp() {
        continueAfterFailure = false
    }

    func testGenerationRSAInKeychain() {
        let keygen = SUKeychain(service: "APP")
        let (publicKey, privateKey) = keygen.generateRsaKeyPair(inKeychain: "monapplication")
        do {
            XCTAssertNotNil(publicKey)
            XCTAssertNotNil(privateKey)
            
            XCTAssertEqual(
                publicKey?.data()?.base64EncodedString()
                ,
                keygen.loadPublicKeyFromKeyChain(key: "monapplication")
            )
            
            XCTAssertEqual(
                privateKey?.data()?.base64EncodedString()
                ,
                keygen.loadPrivateKeyFromKeyChain(key: "monapplication")
            )
        }
    }
    
    func testGenerationRSA() {
        let keyType = kSecAttrKeyTypeRSA as String
        let keySize = 2048
        
        let keygen = SUKeychain(service: "APP")
        
        let (publicKey, privateKey) = keygen.generateRsaKeyPair()
        XCTAssertNotNil(publicKey)
        XCTAssertNotNil(privateKey)
        
        let pvtKeyData = privateKey?.data()
        let pubKeyData = publicKey?.data()
        
        XCTAssertNotNil(pvtKeyData)
        XCTAssertNotNil(pubKeyData)
        
        let exportImportManager = SUCryptoKeysManager()
        if let exportableDERKey = exportImportManager.exportPublicKeyToDER(pubKeyData!, keyType: keyType, keySize: keySize) {
            let fileName = "./publicKey.der"
            do{
                try exportableDERKey.write(to: URL(fileURLWithPath: fileName))
            }catch let error {
                print("\(error)")
            }
            print("Exportable key in DER format:\n\(exportableDERKey.hexDescription)\n")
            let exportablePEMKey = exportImportManager.PEMKeyFromDERKey(exportableDERKey)
            print("Exportable key in PEM format:\n\(exportablePEMKey)\n")
        } else {
            XCTAssert(false)
        }
        
    }
    
    func testimportKey() {
        // first try to get the path for certificate.der
        
        guard let certPath = Bundle(for: RSATests.self).path(forResource: "certificate", ofType: "der") else {
            print("An error happened while reading the certificate file. Unable to get path for certificate.der")
            return
        }
        
        // now get the data from the certificate file
        guard let certData = try? Data(contentsOf: URL(fileURLWithPath: certPath)) else {
            print("An error happened while reading the certificate file. Unable to read certificate.der")
            return
        }
        
        // if we got the certificate data, let's extract the public key reference.
        let importExportManager = SUCryptoKeysManager()
        if let publicKeyRef = importExportManager.importPublicKeyReferenceFromDERCertificate(certData) {
            print("Successfully extracted public key from certificate:\n\(publicKeyRef)\n")
        } else {
            print("Oups! I was unable to retrieve a public key from the certificate.")
        }
    }
    
}
