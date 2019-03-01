//
//  SURsaCrypto.swift
//  SecUtilsSwift
//
//  Created by Ahmed Adouani on 02/2019.
//

import Foundation
import CoreFoundation
import Security
import CommonCrypto

public extension Data {
    var hexDescription: String {
        return self.map { String(format: "%02hhx", $0) }.joined()
    }
}

public extension String {
    
    /// Create `Data` from hexadecimal string representation
    ///
    /// This creates a `Data` object from hex string. Note, if the string has any spaces or non-hex characters (e.g. starts with '<' and with a '>'), those are ignored and only hex characters are processed.
    ///
    /// - returns: Data represented by this hexadecimal string.
    
    var hexadecimal: Data? {
        var data = Data(capacity: count / 2)
        
        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: self, range: NSRange(startIndex..., in: self)) { match, _, _ in
            let byteString = (self as NSString).substring(with: match!.range)
            let num = UInt8(byteString, radix: 16)!
            data.append(num)
        }
        
        guard data.count > 0 else { return nil }
        
        return data
    }
    
}

public extension SecKey {
    
    @available(iOS 10.0, *)
    public func data() -> Data? {
        var error:Unmanaged<CFError>?
        if let cfdata = SecKeyCopyExternalRepresentation(self, &error) {
            let data = cfdata as Data
            return data
        }
        return nil
    }
    
    @available(iOS 10.0, *)
    public func base64Key() -> String? {
        var error:Unmanaged<CFError>?
        if let cfdata = SecKeyCopyExternalRepresentation(self, &error) {
            let data = cfdata as Data
            let b64Key = data.base64EncodedString()
            return b64Key
        }
        return nil
    }
    
    @available(iOS 10.0, *)
    public class func privateKey(from base64Key: String) -> SecKey? {
        guard let data = Data(base64Encoded: base64Key) else {
            return nil
        }
        
        let keyDict:[NSObject:NSObject] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: NSNumber(value: 2048),
            kSecReturnPersistentRef: true as NSObject
        ]
        return SecKeyCreateWithData(data as CFData, keyDict as CFDictionary, nil)
    }
    
    @available(iOS 10.0, *)
    public class func publicKey(from base64Key: String) -> SecKey? {
        guard let data = Data(base64Encoded: base64Key) else {
            return nil
        }
        
        let keyDict:[NSObject:NSObject] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: NSNumber(value: 2048),
            kSecReturnPersistentRef: true as NSObject
        ]
        return SecKeyCreateWithData(data as CFData, keyDict as CFDictionary, nil)
    }
}

public enum CipherTextFormat {
    case base64
    case hex
    case none
}

public class SURsaCrypto {
    public init() {
        
    }
    
    open func encryptString(string: String, publicKey: SecKey, format: CipherTextFormat = .base64) -> String? {
        let stringData = string.data(using: .utf8)! as Data
        return self.encrypt(data: stringData, publicKey: publicKey, format: format)
    }
    
    open func encrypt(data: Data, publicKey: SecKey, format: CipherTextFormat = .base64) -> String? {
        //Encrypt a string with the public key
        let blockSize = SecKeyGetBlockSize(publicKey)
        var messageEncrypted = [UInt8](repeating: 0, count: blockSize)
        var messageEncryptedSize = blockSize
        
        var status: OSStatus!
        
        let codedString = String(data: data, encoding: .utf8)!
        
        status = SecKeyEncrypt(publicKey, SecPadding.PKCS1, codedString, codedString.count, &messageEncrypted, &messageEncryptedSize)
        
        switch status {
        case noErr:
            let encryptedData = Data(bytes: messageEncrypted, count: messageEncryptedSize)
            switch format {
            case .base64:
                return encryptedData.base64EncodedString()
            case .hex:
                return encryptedData.hexDescription
            case .none:
                return String(data: encryptedData, encoding: .utf8)
            }
        default:
            return nil
        }
    }
    
    open func decryptString(encryptedString: String, privateKey: SecKey, format: CipherTextFormat = .base64) -> String? {
        let data = self.decrypt(encryptedString: encryptedString, privateKey: privateKey, format: format)
        return String(data: data!, encoding: .utf8)!
    }
    
    open func decrypt(encryptedString: String, privateKey: SecKey, format: CipherTextFormat = .base64) -> Data? {
        
        var encryptedData: NSData?
        switch format {
        case .base64:
            encryptedData = NSData(base64Encoded: encryptedString)
        case .hex:
            encryptedData = encryptedString.hexadecimal as NSData?
        case .none:
            encryptedData = encryptedString.data(using: .utf8) as NSData?
        }
        
        guard let encryptedBytes = encryptedData?.bytes.assumingMemoryBound(to: UInt8.self) else {
            return nil
        }
        
        //Decrypt the entrypted string with the private key
        let blockSize = SecKeyGetBlockSize(privateKey)
        var messageDecrypted = [UInt8](repeating: 0, count: blockSize)
        var messageDecryptedSize = blockSize
        
        var status: OSStatus!
        status = SecKeyDecrypt(privateKey, SecPadding.PKCS1, encryptedBytes, (encryptedData?.length)!, &messageDecrypted, &messageDecryptedSize)
        
        if status != noErr {
            print("Decryption Error!")
            return nil
        }
        
        return NSData(bytes: messageDecrypted, length: messageDecryptedSize) as Data
    }
    
    open func signString(string: String, privateKey: SecKey, format: CipherTextFormat = .base64) -> String? {
        let stringData = string.data(using: .utf8)! as Data
        return self.sign(data: stringData, privateKey: privateKey, format: format)
    }
    
    open func sign(data: Data, privateKey: SecKey, format: CipherTextFormat = .base64) -> String? {
        let digest = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH))!
        let stringData = data as NSData
        CC_SHA256(stringData.bytes, CC_LONG(stringData.length),
                  digest.mutableBytes.assumingMemoryBound(to: UInt8.self))
        let signedData: NSMutableData = NSMutableData(length: SecKeyGetBlockSize(privateKey))!
        var signedDataLength: Int = signedData.length
        
        let err: OSStatus = SecKeyRawSign(
            privateKey,
            SecPadding.PKCS1SHA256,
            digest.bytes.assumingMemoryBound(to: UInt8.self),
            digest.length,
            signedData.mutableBytes.assumingMemoryBound(to: UInt8.self),
            &signedDataLength
        )
        
        switch err {
        case noErr:
            switch format {
            case .base64:
                return signedData.base64EncodedString()
            case .hex:
                return (signedData as Data).hexDescription
            case .none:
                return String(data: signedData as Data, encoding: .utf8)
            }
        default:
            return nil
        }
        
    }
    
    open func verifyString(string: String, signature: String, publicKey: SecKey, format: CipherTextFormat = .base64) -> Bool {
        let stringData = string.data(using: .utf8)! as Data
        return verify(data: stringData, signature: signature, publicKey: publicKey, format: format)
    }
    
    open func verify(data: Data, signature: String, publicKey: SecKey, format: CipherTextFormat = .base64) -> Bool {
        let digest = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH))!
        
        var signatureData: NSData?
        switch format {
        case .base64:
            signatureData = NSData(base64Encoded: signature)
        case .hex:
            signatureData = signature.hexadecimal as NSData?
        case .none:
            signatureData = signature.data(using: .utf8) as NSData?
        }
        
        guard let _ = signatureData else {
            return false
        }
        
        let stringData = data as NSData

        CC_SHA256(stringData.bytes, CC_LONG(stringData.length),
                  digest.mutableBytes.assumingMemoryBound(to: UInt8.self))
        
        let err: OSStatus = SecKeyRawVerify(
            publicKey,
            SecPadding.PKCS1SHA256,
            digest.bytes.assumingMemoryBound(to: UInt8.self),
            digest.length,
            signatureData!.bytes.assumingMemoryBound(to: UInt8.self),
            signatureData!.length
        )
        
        switch err {
        case noErr:
            return true
        default:
            return false
        }
    }
}
