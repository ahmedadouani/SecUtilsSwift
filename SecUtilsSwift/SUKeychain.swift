//
//  SUKeychain.swift
//  SecUtilsSwift
//
//  Created by Ahmed Adouani on 02/2019.
//

import Foundation

public struct SUSecretItem {
    let service: String
    public private(set) var account: String
    let accessGroup: String?
}

public struct SUKeychain {
    // MARK: Types
    
    enum KeychainError: Error {
        case noSecretFound
        case unexpectedSecretData
        case unexpectedItemData
        case unhandledError(status: OSStatus)
    }
    
    // MARK: Properties
    
    let service: String
    let accessGroup: String?

    // MARK: Intialization
    
    public init(service: String, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }
    
    let PRIVATE_KEY = "PRIVATE_KEY::"
    let PUBLIC_KEY = "PUBLIC_KEY::"
    let KEY_SIZE = 2048
    
    public func generateRsaKeyPair(inKeychain keyId: String) -> (SecKey?, SecKey?)  {
        
        // private key parameters
        let privateKeyParams: [String: AnyObject] = [
            kSecAttrIsPermanent as String: true as AnyObject,
            kSecAttrApplicationTag as String: PRIVATE_KEY + keyId as AnyObject,
            String(kSecAttrAccessible): kSecAttrAccessibleAlways
            ]
        
        // private key parameters
        let publicKeyParams: [String: AnyObject] = [
            kSecAttrApplicationTag as String: PUBLIC_KEY + keyId as AnyObject,
            kSecAttrIsPermanent as String: true as AnyObject,
            String(kSecAttrAccessible): kSecAttrAccessibleAlways
        ]
        
        // global parameters for our key generation
        let parameters: [String: AnyObject] = [
            kSecAttrKeyType as String:          kSecAttrKeyTypeRSA as AnyObject,
            kSecAttrKeySizeInBits as String:    KEY_SIZE as AnyObject,
            kSecPublicKeyAttrs as String:       publicKeyParams as AnyObject,
            kSecPrivateKeyAttrs as String:      privateKeyParams as AnyObject,
            ]
        
        //Ensure that keychain has no key with keyId identifier
        deleteKeyPairFromKeyChain(keyId: keyId)
        
        var publicKey: SecKey?
        var privatekey: SecKey?
        
        let osStatus = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privatekey)
        switch osStatus {
        case noErr:
            return (publicKey, privatekey)
        default:
            return (nil, nil)
        }
    }
    
    public func generateRsaKeyPair() -> (SecKey?, SecKey?)  {
        let parameters: [String: AnyObject] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: KEY_SIZE as AnyObject
        ]
        var publicKey: SecKey?
        var privateKey: SecKey?
        let osStatus = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
        switch osStatus {
        case noErr:
            return (publicKey, privateKey)
        default:
            return (nil, nil)
        }
    }
    
    
    
    // MARK: Keychain access
    
    public func readPassword(account: String) throws -> String  {
        /*
            Build a query to find the item that matches the service, account and
            access group.
        */
        var query = SUKeychain.keychainQuery(withService: service, account: account, accessGroup: accessGroup)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnAttributes as String] = kCFBooleanTrue
        query[kSecReturnData as String] = kCFBooleanTrue
        
        // Try to fetch the existing keychain item that matches the query.
        var queryResult: AnyObject?
        let status = withUnsafeMutablePointer(to: &queryResult) {
            SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
        }
        
        // Check the return status and throw an error if appropriate.
        guard status != errSecItemNotFound else { throw KeychainError.noSecretFound }
        guard status == noErr else { throw KeychainError.unhandledError(status: status) }
        
        // Parse the password string from the query result.
        guard let existingItem = queryResult as? [String : AnyObject],
            let passwordData = existingItem[kSecValueData as String] as? Data,
            let password = String(data: passwordData, encoding: String.Encoding.utf8)
        else {
            throw KeychainError.unexpectedSecretData
        }
        
        return password
    }
    
    public func savePassword(_ password: String, for account: String) throws {
        // Encode the password into an Data object.
        let encodedPassword = password.data(using: String.Encoding.utf8)!
        
        do {
            // Check for an existing item in the keychain.
            try _ = readPassword(account: account)

            // Update the existing item with the new password.
            var attributesToUpdate = [String : AnyObject]()
            attributesToUpdate[kSecValueData as String] = encodedPassword as AnyObject?

            let query = SUKeychain.keychainQuery(withService: service, account: account, accessGroup: accessGroup)
            let status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
            
            // Throw an error if an unexpected status was returned.
            guard status == noErr else { throw KeychainError.unhandledError(status: status) }
        }
        catch KeychainError.noSecretFound {
            /*
                No password was found in the keychain. Create a dictionary to save
                as a new keychain item.
            */
            var newItem = SUKeychain.keychainQuery(withService: service, account: account, accessGroup: accessGroup)
            newItem[kSecValueData as String] = encodedPassword as AnyObject?
            
            // Add a the new item to the keychain.
            let status = SecItemAdd(newItem as CFDictionary, nil)
            
            // Throw an error if an unexpected status was returned.
            guard status == noErr else { throw KeychainError.unhandledError(status: status) }
        }
    }
    
    public mutating func renameAccount(_ account: String, to newAccountName: String) throws {
        // Try to update an existing item with the new account name.
        var attributesToUpdate = [String : AnyObject]()
        attributesToUpdate[kSecAttrAccount as String] = newAccountName as AnyObject?
        
        let query = SUKeychain.keychainQuery(withService: service, account: account, accessGroup: accessGroup)
        let status = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
        
        // Throw an error if an unexpected status was returned.
        guard status == noErr || status == errSecItemNotFound else { throw KeychainError.unhandledError(status: status) }
    }
    
    public func deleteItem(account: String) throws {
        // Delete the existing item from the keychain.
        let query = SUKeychain.keychainQuery(withService: service, account: account, accessGroup: accessGroup)
        let status = SecItemDelete(query as CFDictionary)
        
        // Throw an error if an unexpected status was returned.
        guard status == noErr || status == errSecItemNotFound else { throw KeychainError.unhandledError(status: status) }
    }
    
    public func passwordItems(forService service: String, accessGroup: String? = nil) throws -> [SUSecretItem] {
        // Build a query for all items that match the service and access group.
        var query = SUKeychain.keychainQuery(withService: service, accessGroup: accessGroup)
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        query[kSecReturnAttributes as String] = kCFBooleanTrue
        query[kSecReturnData as String] = kCFBooleanFalse
        
        // Fetch matching items from the keychain.
        var queryResult: AnyObject?
        let status = withUnsafeMutablePointer(to: &queryResult) {
            SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
        }
        
        // If no items were found, return an empty array.
        guard status != errSecItemNotFound else { return [] }

        // Throw an error if an unexpected status was returned.
        guard status == noErr else { throw KeychainError.unhandledError(status: status) }
        
        // Cast the query result to an array of dictionaries.
        guard let resultData = queryResult as? [[String : AnyObject]] else { throw KeychainError.unexpectedItemData }
        
        // Create a `KeychainPasswordItem` for each dictionary in the query result.
        var passwordItems = [SUSecretItem]()
        for result in resultData {
            guard let account  = result[kSecAttrAccount as String] as? String else { throw KeychainError.unexpectedItemData }
            
            let passwordItem = SUSecretItem(service: service, account: account, accessGroup: accessGroup)
            passwordItems.append(passwordItem)
        }
        
        return passwordItems
    }

    // MARK: Convenience
    
    private static func keychainQuery(withService service: String, account: String? = nil, accessGroup: String? = nil) -> [String : AnyObject] {
        var query = [String : AnyObject]()
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecAttrService as String] = service as AnyObject?

        if let account = account {
            query[kSecAttrAccount as String] = account as AnyObject?
        }

        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup as AnyObject?
        }
        
        return query
    }
}

/// Mark:-Utilities
extension SUKeychain {
    //Delete an existing keypair from keychain (public + private)
    public func deleteKeyPairFromKeyChain(keyId: String) {
        deleteRSAKeyFromKeychain(tagName: PRIVATE_KEY + keyId)
        deleteRSAKeyFromKeychain(tagName: PUBLIC_KEY + keyId)
    }
    
    // Delete existing RSA key from keychain
    private func deleteRSAKeyFromKeychain(tagName: String) {
        let queryFilter: [String: AnyObject] = [
            String(kSecClass)             : kSecClassKey,
            String(kSecAttrKeyType)       : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag): tagName as AnyObject
        ]
        let status: OSStatus = SecItemDelete(queryFilter as CFDictionary)
        NSLog("private or public deletion result is: " + status.description)
    }
    
    public func loadPublicKeyFromKeyChain(key: String) -> String? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            String(kSecAttrKeySizeInBits): KEY_SIZE as AnyObject,
            kSecAttrApplicationTag as String: PUBLIC_KEY + key,
            kSecReturnData as String: true
            ] as [String : Any]
        var data: AnyObject?
        let status = SecItemCopyMatching(parameters as CFDictionary, &data)
        if status == errSecSuccess {
            let resultData = data as? NSData
            let resultStr = resultData?.base64EncodedString(options: [])
            return resultStr
        } else {
            print("Error getting public key data: \(status)")
            return nil
        }
    }
    
    public func loadPrivateKeyFromKeyChain(key: String) -> String? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            String(kSecAttrKeySizeInBits): KEY_SIZE as AnyObject,
            kSecAttrApplicationTag as String: PRIVATE_KEY + key,
            kSecReturnData as String: true
            ] as [String : Any]
        var data: AnyObject?
        let status = SecItemCopyMatching(parameters as CFDictionary, &data)
        if status == errSecSuccess {
            let resultData = data as? NSData
            let resultStr = resultData?.base64EncodedString(options: [])
            return resultStr
        } else {
            print("Error getting private key data: \(status)")
            return nil
        }
    }
}
