package domain

import "fmt"

type BusinessError struct {
	error
	Code    string `json:"code"`
	Message string `json:"message"`
}

type InfraError struct {
	error
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Error interface {
	GetCode() string
	GetMessage() string
}

var (
	// ErrInvalidCredentials is returned when credentials are invalid
	ErrInvalidCredentials = NewBusinessError("U0001", "Invalid credentials")

	// ErrInvalidClient is returned when the client is invalid
	ErrInvalidClient = NewBusinessError("U0002", "Invalid client")

	// ErrInvalidAuthorizationCode is returned when the authorization code is invalid
	ErrInvalidAuthorizationCode = NewBusinessError("U0003", "Invalid authorization code")

	// ErrAuthorizationCodeExpired is returned when the authorization code is expired
	ErrAuthorizationCodeExpired = NewBusinessError("U0004", "Authorization code expired")

	// ErrInvalidPKCE is returned when the PKCE is invalid
	ErrInvalidPKCE = NewBusinessError("U0005", "Invalid PKCE")

	// ErrNotFound is returned when a user is not found
	errNotFound = func(t string) *BusinessError {
		return NewBusinessError("U0007", fmt.Sprintf("%s not found", t))
	}

	ErrUserNotFound = errNotFound("User")

	// ErrInvalid is returned when a user is invalid
	ErrInvalid = func(t string) *BusinessError {
		return NewBusinessError("U0008", fmt.Sprintf("%s is invalid", t))
	}

	ErrClientNotFound = errNotFound("Client")

	// ErrAlreadyExists is returned when a user already exists
	ErrAlreadyExists = func(t string) *BusinessError { return NewBusinessError("U0009", fmt.Sprintf("%s already exists", t)) }

	ErrClientAlreadyExists = func(t string) *BusinessError { return ErrAlreadyExists(t) }("Client")

	ErrUserAlreadyExists = func(t string) *BusinessError { return ErrAlreadyExists(t) }("User")

	// ErrInvalidScope is returned when the scope is invalid
	ErrInvalidScope = NewBusinessError("U0010", "Invalid scope")

	// ErrInvalidField is returned when the field is invalid
	ErrInvalidField = NewBusinessError("U0011", "Invalid field")

	// ErrPathNotFound is returned when the path is not found
	ErrPathNotFound = NewBusinessError("U0012", "Path parameter not found")

	// ErrInvalidRequestBody is returned when the request body is invalid
	ErrInvalidRequestBody = NewBusinessError("U0013", "Invalid request body")

	// ErrUnauthorized is returned when the user is not authenticated
	ErrUnauthorized = NewBusinessError("U0014", "Unauthorized")

	// ErrInternal is returned when there is an internal server error
	ErrInternal = NewInfraError("U0015", "Internal server error")

	// ErrFailedGenerateToken is returned when the scope is invalid
	ErrFailedGenerateToken = NewInfraError("U0016", "Failed to generate token")

	// ErrForbidden is returned when the user is forbidden
	ErrForbidden = NewBusinessError("U0018", "Forbidden")

	// ErrInvalidToken is returned when the token is invalid
	ErrInvalidToken = NewBusinessError("U0019", "Invalid token")

	// ErrInvalidDuration is returned when the duration is invalid
	ErrInvalidDuration = func(message string) *BusinessError { return NewBusinessError("U0020", message) }

	// ErrTokenExpired is returned when the token is expired
	ErrTokenExpired = NewBusinessError("U0021", "Token expired")

	// ErrTokenIssuedInFuture is returned when the token is issued in the future
	ErrTokenIssuedInFuture = NewBusinessError("U0021", "Token issued in the future")

	// ErrTokenNotYetValid is returned when the token is not yet valid
	ErrTokenNotYetValid = NewBusinessError("U0022", "Token not yet valid")

	// ErrTokenNoRoles is returned when the token has no roles
	ErrTokenNoRoles = NewBusinessError("U0023", "Token has no roles")

	// ErrTokenSubjectRequired is returned when the token subject is required
	ErrTokenSubjectRequired = NewBusinessError("U0024", "Token subject is required")

	// ErrInvalidClaims is returned when the claims are invalid
	ErrInvalidClaims = NewBusinessError("U0025", "Invalid claims")

	// ErrTokenBlacklisted is returned when the token is blacklisted
	ErrTokenBlacklisted = NewBusinessError("U0026", "Token blacklisted")

	// ErrTokenGeneration is returned when the token generation fails
	ErrTokenGeneration = NewInfraError("U0027", "Failed to generate token")

	// ErrInvalidKeyConfig is returned when the key configuration is invalid
	ErrInvalidKeyConfig = NewInfraError("U0028", "Invalid key configuration")

	// ErrInvalidSigningMethod is returned when the signing method is invalid
	ErrInvalidSigningMethod = NewBusinessError("U0029", "Invalid signing method")

	// ErrInvalidSignature is returned when the signature is invalid
	ErrInvalidSignature = NewBusinessError("U0030", "Invalid signature")

	// ErrInvalidRedirectURI is returned when the redirect URI is invalid
	ErrInvalidRedirectURI = NewBusinessError("U0031", "Invalid redirect URI")

	// ErrInvalidCodeChallengeMethod is returned when the code challenge method is invalid
	ErrInvalidCodeChallengeMethod = NewBusinessError("U0032", "Invalid code challenge method")

	// ErrInvalidCodeChallenge is returned when the code challenge is invalid
	ErrInvalidCodeChallenge = NewBusinessError("U0033", "Invalid code challenge")

	// ErrEmailNotVerified is returned when the email is not verified
	ErrEmailNotVerified = NewBusinessError("U0034", "Email not verified")

	// ErrInvalidVerificationCode is returned when the verification code is invalid
	ErrInvalidVerificationCode = NewBusinessError("U0035", "Invalid verification code")

	// ErrVerificationCodeExpired is returned when the verification code is expired
	ErrVerificationCodeExpired = NewBusinessError("U0036", "Verification code expired")

	// ErrInvalidPasswordChangeCode is returned when the password change code is invalid
	ErrInvalidPasswordChangeCode = NewBusinessError("U0037", "Invalid password change code")

	// ErrPasswordChangeCodeExpired is returned when the password change code is expired
	ErrPasswordChangeCodeExpired = NewBusinessError("U0038", "Password change code expired")

	// ErrEmailSendFailed is returned when sending email fails
	ErrEmailSendFailed = NewInfraError("U0039", "Failed to send email")

	// ErrMissingSMTPConfiguration is returned when the email is invalid
	ErrMissingSMTPConfiguration = NewBusinessError("U0040", "missing necessary SMTP configuration")

	// ErrInvalidEmail is returned when the email is invalid
	ErrInvalidEmail = NewBusinessError("U0041", "invalid email address")

	// ErrTokenSignatureInvalid is returned when the token signature is invalid
	ErrTokenSignatureInvalid = NewBusinessError("U0042", "Token signature is invalid")

	// ErrTokenMalformed is returned when the token is malformed
	ErrTokenMalformed = NewBusinessError("U0043", "Token malformed")

	// ErrTokenHasNoRoles is returned when the token has no roles
	ErrTokenHasNoRoles = NewBusinessError("U0044", "Token has no roles")

	// TOTP related errors
	ErrTOTPNotEnabled            = NewBusinessError("U0045", "TOTP is not enabled for this user")
	ErrTOTPAlreadyEnabled        = NewBusinessError("U0046", "TOTP is already enabled for this user")
	ErrInvalidTOTPCode           = NewBusinessError("U0047", "Invalid TOTP code")
	ErrTOTPSecretGeneration      = NewInfraError("U0048", "Failed to generate TOTP secret")
	ErrTOTPQRGeneration          = NewInfraError("U0049", "Failed to generate TOTP QR code")
	ErrTOTPBackupCodesGeneration = NewInfraError("U0050", "Failed to generate TOTP backup codes")
	ErrInvalidTOTPBackupCode     = NewBusinessError("U0051", "Invalid TOTP backup code")
	ErrTOTPBackupCodesExhausted  = NewBusinessError("U0052", "All TOTP backup codes have been used")
	ErrTOTPVerificationRequired  = NewBusinessError("U0053", "TOTP verification required")
	ErrInvalidMFATicket          = NewBusinessError("U0054", "Invalid MFA ticket")
	ErrMFATicketExpired          = NewBusinessError("U0055", "MFA ticket expired")
	ErrMFATicketAlreadyUsed      = NewBusinessError("U0056", "MFA ticket already used")

	// ErrInvalidUserID is returned when the user ID is invalid
	ErrInvalidUserID = NewBusinessError("U0057", "Invalid user ID")

	// Account related errors
	ErrAccountNotFound        = errNotFound("Account")
	ErrAccountCreationFailed  = NewInfraError("U0058", "Failed to create account")
	ErrAccountUpdateFailed    = NewInfraError("U0059", "Failed to update account")
	ErrAccountDeleteFailed    = NewInfraError("U0060", "Failed to delete account")
)

func (e *BusinessError) GetCode() string {
	return e.Code
}

func (e *BusinessError) GetMessage() string {
	return e.Message
}

func (e *InfraError) GetCode() string {
	return e.Code
}

func (e *InfraError) GetMessage() string {
	return e.Message
}

func NewBusinessError(code, message string) *BusinessError {
	return &BusinessError{
		error:   fmt.Errorf("%s: %s", code, message),
		Code:    code,
		Message: message,
	}
}

func NewInfraError(code, message string) *InfraError {
	return &InfraError{
		error:   fmt.Errorf("%s: %s", code, message),
		Code:    code,
		Message: message,
	}
}
