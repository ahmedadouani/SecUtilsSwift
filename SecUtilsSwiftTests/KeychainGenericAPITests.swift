//
//  KeychainPasswordItemTests.swift
//  RSA_AES_SwiftTests
//
//  Created by Ahmed Adouani on 27/02/2019.
//  Copyright © 2019 Ignacio Nieto Carvajal. All rights reserved.
//

import XCTest
@testable import SecUtilsSwift

class KeychainGenericAPITests: XCTestCase {

    override func setUp() {
        continueAfterFailure = false
    }

    func testExample() {
        let serviceName = "myservice<>myApp"
        let originalAccountName = "account"
        let accessGroup: String? = nil//"accessGroup"
        var keychainApi = SUKeychain(service: serviceName, accessGroup: accessGroup)
        
        let newAccountName = "newAccountName"
        let newPassword = "newPassword"
        
        // Update the account name and password.
        try? keychainApi.renameAccount(originalAccountName, to: newAccountName)
        try? keychainApi.savePassword(newPassword, for: newAccountName)
        
        //try? keychainApi.deleteItem(account: newAccountName)
        
        do {
            let passwordItems = try keychainApi.passwordItems(forService: serviceName, accessGroup: accessGroup)
            print("passwordItems: \(passwordItems)")
        
            let password = try? keychainApi.readPassword(account: passwordItems.last!.account)
            print("password: \(password!)")
        }
        catch {
            fatalError("Error fetching password items - \(error)")
        }
        
    }
}
