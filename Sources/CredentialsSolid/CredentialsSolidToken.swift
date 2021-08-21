
import Kitura
import KituraNet
import LoggerAPI
import Credentials
import HeliumLogger
import Foundation
import LoggerAPI
import SolidAuthSwiftTools

/// Authentication a Solid Pod id token.
public class CredentialsSolidToken: CredentialsPluginProtocol, CredentialsTokenTTL {
    public static let tokenType = "SolidToken"

    /// The name of the plugin.
    public var name: String {
        return Self.tokenType
    }
    
    /// An indication as to whether the plugin is redirecting or not.
    public var redirecting: Bool {
        return false
    }
    
    /// The time in seconds since the user profile was generated that the access token will be considered valid.
    public let tokenTimeToLive: TimeInterval?
    
    private var delegate: UserProfileDelegate?
    private var codeParameters: CodeParameters!
    private let decoder = JSONDecoder()
    private var jwksRequest:JwksRequest!
    private var accountId: String!
    
    /// A delegate for `UserProfile` manipulation.
    public var userProfileDelegate: UserProfileDelegate? {
        return delegate
    }
    
    /// Initialize a `CredentialsSolidToken` instance.
    ///
    public init(tokenTimeToLive: TimeInterval? = nil) {
        self.tokenTimeToLive = tokenTimeToLive
    }
    
    /// User profile cache.
    public var usersCache: NSCache<NSString, BaseCacheElement>?
    
    /// In the UserProfile `extendedProperties`, the codeParametersKey will have a value of the CodeParameters.
    public static let codeParametersKey = "codeParameters"
    
    private let tokenTypeKey = "X-token-type"
    private let idTokenKey = "id-token"
    
    /// Will contain the base64 encoded CodeParameters
    private let accountDetailsKey = "X-account-details"
    
    /// Will have the sub aka. webid for the Solid user.
    // This is redundant with the value in the TokenClaims, but on the main server I want to be able to easily pull the account id from the headers and not make another Solid server request to decrypt the TokenClaims after the decryption here.
    private let accountIdKey = "X-account-id"
    
    /// Authenticate incoming request using Apple Sign In OAuth2 token.
    ///
    /// - Parameter request: The `RouterRequest` object used to get information
    ///                     about the request.
    /// - Parameter response: The `RouterResponse` object used to respond to the
    ///                       request.
    /// - Parameter options: The dictionary of plugin specific options.
    /// - Parameter onSuccess: The closure to invoke in the case of successful authentication.
    /// - Parameter onFailure: The closure to invoke in the case of an authentication failure.
    /// - Parameter onPass: The closure to invoke when the plugin doesn't recognize the
    ///                     authentication token in the request.
    /// - Parameter inProgress: The closure to invoke to cause a redirect to the login page in the
    ///                     case of redirecting authentication.
    public func authenticate(request: RouterRequest, response: RouterResponse,
                             options: [String:Any], onSuccess: @escaping (UserProfile) -> Void,
                             onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                             onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                             inProgress: @escaping () -> Void) {

        let type = request.headers[tokenTypeKey]
        let idToken = request.headers[idTokenKey]
        let base64CodeParametersString = request.headers[accountDetailsKey]
        let accountId = request.headers[accountIdKey]

        authenticate(type: type, idToken: idToken, base64CodeParametersString: base64CodeParametersString, accountId: accountId,  options: options, onSuccess: onSuccess, onFailure: onFailure, onPass: onPass)
    }
    
    // Split away from the main `authenticate` function for testing purposes.
    func authenticate(type: String?, idToken: String?, base64CodeParametersString: String?, accountId: String?, options: [String:Any], onSuccess: @escaping (UserProfile) -> Void, onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void, onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void) {

        guard let type = type, type == name else {
            onPass(nil, nil)
            return
        }
        
        guard let idToken = idToken else {
            onFailure(nil, nil)
            return
        }

        guard let accountId = accountId else {
            onFailure(nil, nil)
            return
        }
        
        self.accountId = accountId
        
        guard let base64CodeParametersString = base64CodeParametersString else {
            onFailure(nil, nil)
            return
        }
        
        guard let codeParametersData = Data(base64Encoded: base64CodeParametersString) else {
            onFailure(nil, nil)
            return
        }
            
        do {
            self.codeParameters = try JSONDecoder().decode(CodeParameters.self, from: codeParametersData)
        } catch let error {
            Log.error("Could not decode CodeParameters: \(error)")
            onFailure(nil, nil)
            return
        }
        
        getProfileAndCacheIfNeeded(token: idToken, options: options, onSuccess: onSuccess, onFailure: onFailure)
    }

    enum CredentialsSolidTokenError: Swift.Error {
        case nilUserProfile
    }
    
    // Validate the id token provided by the user-- to the extent we can (without checking its expiry).
    public func generateNewProfile(token: String, options: [String:Any], completion: @escaping (CredentialsTokenTTLResult) -> Void) {

        jwksRequest = JwksRequest(jwksURL: self.codeParameters.jwksURL)
        jwksRequest.send { [weak self] result in
            guard let self = self else { return }
            
            switch result {
            case .failure(let error):
                let result = CredentialsTokenTTLResult.error(error)
                completion(result)
                
            case .success(let response):
                let tokenObject: Token
                do {
                    tokenObject = try Token(token, jwks: response.jwks)
                } catch let error {
                    let result = CredentialsTokenTTLResult.error(error)
                    completion(result)
                    return
                }
                
                // Have not validated the Token object: Its expiry is known to go out of date.
                
                guard let userProfile = self.createUserProfile(from: tokenObject.claims) else {
                    let result = CredentialsTokenTTLResult.error(CredentialsSolidTokenError.nilUserProfile)
                    completion(result)
                    return
                }
                
                completion(.success(userProfile))
            }
        }
    }
    
    func createUserProfile(from claims:TokenClaims) -> UserProfile? {
        var id: String!
                
        if let webid = claims.webid {
            id = webid
        }
        else if let sub = claims.sub {
            id = sub
        }
        else {
            Log.error("Could not get webid or sub from claims")
            return nil
        }
        
        guard self.accountId == id else {
            Log.error("HTTP header account id \(String(describing: self.accountId)) didn't match that in TokenClaims: \(String(describing: id))")
            return nil
        }
            
        guard let codeParameters = codeParameters else {
            Log.error("nil codeParameters")
            return nil
        }
        
        return UserProfile(id: id, displayName: "", provider: self.name, name: nil, emails: nil, photos: nil, extendedProperties: [Self.codeParametersKey : codeParameters])
    }
}
