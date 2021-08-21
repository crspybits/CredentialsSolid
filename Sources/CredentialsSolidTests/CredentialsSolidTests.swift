//
//  CredentialsSolidTests.swift
//  
//
//  Created by Christopher G Prince on 8/15/21.
//

import Foundation
import XCTest
@testable import CredentialsSolid
import HeliumLogger
import LoggerAPI

// Run tests:
//  swift test --enable-test-discovery

struct Credentials: Codable {
    let idToken: String
    let accountDetails: String
    
    // The webid aka. sub for the user.
    let accountId: String
}

final class CredentialsSolidTests: XCTestCase {
    let credsFileURL = URL(fileURLWithPath: "/root/Apps/Private/CredentialsSolid/CredsFromiOSSolid.json")
    
    func loadCredentials() -> Credentials? {
        do {
            let credentialsData = try Data(contentsOf: credsFileURL)
            return try JSONDecoder().decode(Credentials.self, from: credentialsData)
        } catch let error {
            print("Error: \(error)")
            return nil
        }
    }
    
    let credentialsSolidToken = CredentialsSolidToken()
    var credentials: Credentials?
    
    override func setUp() {
        super.setUp()
        HeliumLogger.use(.debug)
        credentials = loadCredentials()
        
        // Looks like Kitura Credentials sets this up. So, we've got to.
        credentialsSolidToken.usersCache = NSCache()
    }

    func testWithNoTypePasses() {
        var pass = false
        
        credentialsSolidToken.authenticate(type: nil, idToken: nil, base64CodeParametersString: nil, accountId: nil, options: [:],
        onSuccess: { profile in
            XCTFail()
        },
        onFailure: { httpStatusCode, dict in
            XCTFail()
        },
        onPass: { httpStatusCode, dict in
            // Expected
            pass = true
        })
        
        XCTAssert(pass)
    }
    
    func testWithWrongTypePasses() {
        var pass = false
        
        credentialsSolidToken.authenticate(type: "Foobar", idToken: nil, base64CodeParametersString: nil, accountId: nil, options: [:],
        onSuccess: { profile in
            XCTFail()
        },
        onFailure: { httpStatusCode, dict in
            XCTFail()
        },
        onPass: { httpStatusCode, dict in
            // Expected
            pass = true
        })
        
        XCTAssert(pass)
    }
    
    func testWithOnlyTypeFails() {
        var fail = false
        
        credentialsSolidToken.authenticate(type: CredentialsSolidToken.tokenType, idToken: nil, base64CodeParametersString: nil, accountId: nil, options: [:],
        onSuccess: { profile in
            XCTFail()
        },
        onFailure: { httpStatusCode, dict in
            // Expected
            fail = true
        },
        onPass: { httpStatusCode, dict in
            XCTFail()
        })
        
        XCTAssert(fail)
    }
    
    func testWithOnlyTypeAndIdTokenFails() {
        guard let credentials = credentials else {
            XCTFail()
            return
        }
        
        var fail = false
        
        credentialsSolidToken.authenticate(type: CredentialsSolidToken.tokenType, idToken: credentials.idToken, base64CodeParametersString: nil, accountId: nil, options: [:],
        onSuccess: { profile in
            XCTFail()
        },
        onFailure: { httpStatusCode, dict in
            // Expected
            fail = true
        },
        onPass: { httpStatusCode, dict in
            XCTFail()
        })
        
        XCTAssert(fail)
    }

    func testWithTypeIdTokenAndBadCodeParameterStringFails() {
        guard let credentials = credentials else {
            XCTFail()
            return
        }
        
        var fail = false
        
        credentialsSolidToken.authenticate(type: CredentialsSolidToken.tokenType, idToken: credentials.idToken, base64CodeParametersString: "Foo", accountId: nil, options: [:],
        onSuccess: { profile in
            XCTFail()
        },
        onFailure: { httpStatusCode, dict in
            // Expected
            fail = true
        },
        onPass: { httpStatusCode, dict in
            XCTFail()
        })
        
        XCTAssert(fail)
    }
    
    func testWithValidTypeIdTokenAndCodeParametersWorks() {
        guard let credentials = credentials else {
            XCTFail()
            return
        }
        
        let exp = expectation(description: "exp")
        
        credentialsSolidToken.authenticate(type: CredentialsSolidToken.tokenType, idToken: credentials.idToken, base64CodeParametersString: credentials.accountDetails, accountId: credentials.accountId, options: [:],
        onSuccess: { profile in
            Log.debug("profile.id: \(profile.id)")
            exp.fulfill()
        },
        onFailure: { httpStatusCode, dict in
            XCTFail("httpStatusCode: \(String(describing:httpStatusCode)); dict: \(String(describing: dict))")
            exp.fulfill()
        },
        onPass: { httpStatusCode, dict in
            XCTFail()
            exp.fulfill()
        })
        
        waitForExpectations(timeout: 10, handler: nil)
    }
    
    func testWithValidTypeIdTokenAndCodeParametersButBadAccountIdFails() {
        guard let credentials = credentials else {
            XCTFail()
            return
        }
        
        let exp = expectation(description: "exp")
        
        credentialsSolidToken.authenticate(type: CredentialsSolidToken.tokenType, idToken: credentials.idToken, base64CodeParametersString: credentials.accountDetails, accountId: "Foobly", options: [:],
        onSuccess: { profile in
            XCTFail()
            exp.fulfill()
        },
        onFailure: { httpStatusCode, dict in
            exp.fulfill()
        },
        onPass: { httpStatusCode, dict in
            XCTFail()
            exp.fulfill()
        })
        
        waitForExpectations(timeout: 10, handler: nil)
    }
    
    func testWithTypeBadIdTokenAndValidCodeParameterStringFails() {
        guard let credentials = credentials else {
            XCTFail()
            return
        }
        
        let exp = expectation(description: "exp")
        
        credentialsSolidToken.authenticate(type: CredentialsSolidToken.tokenType, idToken: "Foobar", base64CodeParametersString: credentials.accountDetails, accountId: nil, options: [:],
        onSuccess: { profile in
            XCTFail()
            exp.fulfill()
        },
        onFailure: { httpStatusCode, dict in
            // Expected
            exp.fulfill()
        },
        onPass: { httpStatusCode, dict in
            XCTFail()
            exp.fulfill()
        })
        
        waitForExpectations(timeout: 10, handler: nil)
    }
}
