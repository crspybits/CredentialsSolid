
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
    private var serverParameters: ServerParameters!
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
    
    /// In the UserProfile `extendedProperties`, the serverParametersKey will have a value of the ServerParameters.
    public static let serverParametersKey = "serverParameters"
    
    private let tokenTypeKey = "X-token-type"
    private let idTokenKey = "id-token"
    
    /// Will contain the base64 encoded ServerParameters
    private let accountDetailsKey = "X-account-details"
    
    /// Will have the webid for the Solid user.
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
        let base64ServerParametersString = request.headers[accountDetailsKey]
        let accountId = request.headers[accountIdKey]

        authenticate(type: type, idToken: idToken, base64ServerParametersString: base64ServerParametersString, accountId: accountId,  options: options, onSuccess: onSuccess, onFailure: onFailure, onPass: onPass)
    }
    
    // Split away from the main `authenticate` function for testing purposes.
    func authenticate(type: String?, idToken: String?, base64ServerParametersString: String?, accountId: String?, options: [String:Any], onSuccess: @escaping (UserProfile) -> Void, onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void, onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void) {

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
        
        guard let base64ServerParametersString = base64ServerParametersString else {
            onFailure(nil, nil)
            return
        }
        
        guard let serverParametersData = Data(base64Encoded: base64ServerParametersString) else {
            onFailure(nil, nil)
            return
        }
            
        do {
            self.serverParameters = try JSONDecoder().decode(ServerParameters.self, from: serverParametersData)
        } catch let error {
            Log.error("Could not decode ServerParameters: \(error)")
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

        jwksRequest = JwksRequest(jwksURL: self.serverParameters.jwksURL)
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
                
                Log.debug("Expiry: \(String(describing: tokenObject.claims.exp))")
                
                // Have not validated the Token object: Its expiry is known to go out of date.
                
                guard let accountId = self.accountId,
                    let userProfile = self.createUserProfile(from: tokenObject.claims, accountId: accountId) else {
                    let result = CredentialsTokenTTLResult.error(CredentialsSolidTokenError.nilUserProfile)
                    completion(result)
                    return
                }
                
                completion(.success(userProfile))
            }
        }
    }
    
    func createUserProfile(from claims:TokenClaims, accountId: String) -> UserProfile? {
        guard let serverParameters = serverParameters else {
            Log.error("nil serverParameters")
            return nil
        }

        var id: String?

        if let webid = claims.webid {
            id = webid
        }
        else if let sub = claims.sub {
            id = sub
        }

        // I am not requiring the TokenClaims to have a webid because of the description here: https://github.com/crspybits/SolidAuthSwift/issues/7
        // i.e., it seems that some times the web id will not be in the TokenClaims.
        // BUT: If there *is* a webid in the TokenClaims, it ought to match that passed in the accountId.
        
        if let id = id {
            guard accountId == id else {
                Log.error("There was a webid in the claims: \(id) but it didn't match that passed: \(accountId).")
                return nil
            }
        }
        
        return UserProfile(id: accountId, displayName: "", provider: self.name, name: nil, emails: nil, photos: nil, extendedProperties: [Self.serverParametersKey : serverParameters])
    }
}
