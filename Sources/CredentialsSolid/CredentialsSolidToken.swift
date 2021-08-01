
import Kitura
import KituraNet
import LoggerAPI
import Credentials
import HeliumLogger
import Foundation
import LoggerAPI
import SolidAuthSwiftTools

public let tokenType = "SolidToken"

/// extendedProperties in the UserProfile will have the key `solidServerPacketKey`
/// with a ServerPacket value.
public let solidServerPacketKey = "solidServerPacket"

/// Authentication a Solid Pod id token.
public class CredentialsSolidToken: CredentialsPluginProtocol, CredentialsTokenTTL {
    /// The name of the plugin.
    public var name: String {
        return tokenType
    }
    
    /// An indication as to whether the plugin is redirecting or not.
    public var redirecting: Bool {
        return false
    }
    
    /// The time in seconds since the user profile was generated that the access token will be considered valid.
    public let tokenTimeToLive: TimeInterval?
    
    private var delegate: UserProfileDelegate?
    private var serverPacket: ServerPacket!
    private let decoder = JSONDecoder()
    private var jwksRequest:JwksRequest!
    
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
    
    private let tokenTypeKey = "X-token-type"
    private let idTokenKey = "id-token"
    
    /// Will contain the base64 encoded ServerPacket
    private let accountDetailsKey = "X-account-details"
    
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

        guard let type = request.headers[tokenTypeKey], type == name else {
            onPass(nil, nil)
            return
        }
        
        guard let idToken = request.headers[idTokenKey] else {
            onFailure(nil, nil)
            return
        }

        guard let base64ServerPacketString = request.headers[accountDetailsKey] else {
            onFailure(nil, nil)
            return
        }

        guard let serverPacketData = Data(base64Encoded: base64ServerPacketString) else {
            onFailure(nil, nil)
            return
        }
            
        do {
            self.serverPacket = try JSONDecoder().decode(ServerPacket.self, from: serverPacketData)
        } catch let error {
            Log.error("Could not decode ServerPacket: \(error)")
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

        jwksRequest = JwksRequest(jwksURL: self.serverPacket.parameters.jwksURL)
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
                
                // Will not validate the Token object: Its expiry is known to go out of date.
                
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
        guard let webid = claims.webid else {
            return nil
        }
        
        guard let serverPacket = self.serverPacket else {
            return nil
        }
        
        var userEmails: [UserProfile.UserProfileEmail]?
        if let email = serverPacket.email {
            userEmails = [UserProfile.UserProfileEmail(value: email, type: "")]
        }
        
        return UserProfile(id: webid, displayName: serverPacket.username ?? "", provider: self.name, name: nil, emails: userEmails, photos: nil, extendedProperties: [solidServerPacketKey: serverPacket])
    }
}
