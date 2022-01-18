package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/go-playground/validator"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/labstack/echo/v4/middleware"
)

type (
	// App struct provides basic information to connect to the
	// Cognito UserPool on AWS.
	App struct {
		CognitoClient   *cognito.CognitoIdentityProvider
		UserPoolID      string
		AppClientID     string
		AppClientSecret string
		Token           string
	}

	User struct {
		// UUID Is a generated uuid to recognize the user,
		// this is not useful at this moment but it could be so
		// in the future
		UUID uuid.UUID `json:"uuid" db:"uuid"`

		// Username is the username decided by the user
		// at signup time. This field is not required but it could
		// be useful to have
		Username string `json:"username" validate:"required" db:"username"`

		// Password is the password decided by the user
		// at signup time. This field is required and no signup
		// can work without this.
		// To create a secure password, contraints on this field are
		// it must contain an uppercase and lowercase letter,
		// a special symbol and a number.
		Password string `json:"password" validate:"required"`

		// Email is the user email used at signup time.
		// this is a required field and must be used at login time.

	}
	UserForgot struct {
		Username string `json:"username" validate:"required"`
	}

	UserConfirmationCode struct {
		ConfirmationCode string `json:"confirmationCode" validate:"required"`
		User             User   `json:"user" validate:"required"`
	}
	UserRegister struct {
		Email string `json:"email" validate:"required" db:"email"`
		User  User   `json:"user" validate:"required"`
	}

	// UserLogin struct {
	// 	Email string `json:"email" db:"email"`
	// 	User  User   `json:"user" validate:"required"`
	// }

	// OTP is the struct to handle otp verification.
	OTP struct {
		// Username is the user's username, this is necessary because
		// cognito.ConfirmSignUpInput structure requires this field
		Username string `json:"username"`

		// OTP is the otp code received via email or phone.
		OTP string `json:"otp"`
	}

	// Response is used to handle and return errors from the server.
	// These errors could come from AWS or Server side.
	Response struct {
		Error error `json:"error"`
	}

	CustomValidator struct {
		validator *validator.Validate
	}
)

func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.validator.Struct(i); err != nil {
		// Optionally, you could return the error to give each route more control over the status code
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return nil
}

func validateUser(sl validator.StructLevel) {
	if len(sl.Current().Interface().(User).Username) == 0 || len(sl.Current().Interface().(User).Password) == 0 {
		sl.ReportError(sl.Current().Interface(), "User", "", "", "")
	}
}

func main() {

	// Setup The AWS Region and AWS session
	conf := &aws.Config{Region: aws.String("eu-west-1")}
	mySession := session.Must(session.NewSession(conf))

	// Fill App structure with environment keys and session generated
	a := App{
		CognitoClient:   cognito.New(mySession),
		UserPoolID:      os.Getenv("COGNITO_USER_POOL_ID"),
		AppClientID:     os.Getenv("COGNITO_APP_CLIENT_ID"),
		AppClientSecret: os.Getenv("COGNITO_APP_CLIENT_SECRET"),
	}

	// Echo stuff
	e := echo.New()
	validate := &CustomValidator{validator: validator.New()}
	validate.validator.RegisterStructValidation(validateUser, User{})

	e.Validator = validate

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
	}))

	registerFunc := func(c echo.Context) error {
		return a.Register(c, *validate.validator)
	}

	e.POST("/auth/register", registerFunc)

	e.POST("/auth/login", a.Login)

	e.POST("/auth/otp", a.OTP)

	//e.POST("/auth/verify", a.Verify)

	e.GET("/auth/forgot", a.ForgotPassword)

	confirmForgotPasswordFunc := func(c echo.Context) error {
		return a.ConfirmForgotPassword(c, *validate.validator)
	}
	e.POST("/auth/confirmforgot", confirmForgotPasswordFunc)

	logoutHandler := func(c echo.Context) error {

		logoutURI := "https://exampleusers.auth.eu-west-1.amazoncognito.com/logout?" + "client_id=" + a.AppClientID + "&logout_uri=https://tiruma.io"
		fmt.Println(logoutURI)
		_, err := http.Get(logoutURI)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		return nil
	}
	e.GET("/auth/logout", logoutHandler)
	e.Logger.Fatal(e.Start(":1323"))
}

// Register receiver method is the handler for
// /register endpoint, this method takes echo.Context
// in which is located the user input as json request
// as input with the following format:
// {
//     "email":"example@email.com",
//     "user":{
//         "username":"exampleusername",
//         "password":"Hello4world!"
//     }
// }
// and returns a Json containing the error with this format:
// {
//     "error": {
//         "Message_": "Example message error"
//     }
// }
func (a *App) Register(c echo.Context, v validator.Validate) (err error) {

	r := new(Response)
	u := new(UserRegister)
	u.User.UUID = uuid.New()

	// Bind the user input saved in context to the u(User) variable and validate it
	if err = c.Bind(u); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err = c.Validate(u); err != nil {
		return err
	}
	if err = v.Struct(u.User); err != nil {
		return err
	}

	user := &cognito.SignUpInput{
		Username: aws.String(u.User.Username),
		Password: aws.String(u.User.Password),
		ClientId: aws.String(a.AppClientID),
		UserAttributes: []*cognito.AttributeType{
			{
				Name:  aws.String("email"),
				Value: aws.String(u.Email),
			},
		},
	}

	secretHash := computeSecretHash(a.AppClientSecret, u.User.Username, a.AppClientID)
	user.SecretHash = aws.String(secretHash)

	// Make signup operation using cognito's api
	_, r.Error = a.CognitoClient.SignUp(user)
	if r.Error != nil {
		return c.JSON(http.StatusInternalServerError, r)
	}

	return c.JSON(http.StatusOK, r)
}

// OTP receiver method is the handler for
// /otp endpoint, this method takes echo.Context
// in which is located the user input as json request
// as input with the following format:
// {
//     "username":"exampleusername",
//     "otp":"123456"
// }
// otp field is received via email
// and returns a Json containing the error with this format:
// {
//     "error": {
//         "Message_": "Example message error"
//     }
// }

func (a *App) OTP(c echo.Context) (err error) {

	r := new(Response)
	o := new(OTP)

	if err = c.Bind(o); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err = c.Validate(o); err != nil {
		return err
	}

	user := &cognito.ConfirmSignUpInput{
		ConfirmationCode: aws.String(o.OTP),
		Username:         aws.String(o.Username),
		ClientId:         aws.String(a.AppClientID),
	}

	secretHash := computeSecretHash(a.AppClientSecret, o.Username, a.AppClientID)
	user.SecretHash = aws.String(secretHash)

	_, r.Error = a.CognitoClient.ConfirmSignUp(user)
	if err != nil {
		fmt.Println(err)
		return c.JSON(http.StatusInternalServerError, r)
	}

	return c.JSON(http.StatusOK, r)
}

// Login receiver method is the handler for
// /login endpoint, this method takes echo.Context
// in which is located the user input as json request
// as input with the following format:
// {
//     "username":"exampleusername",
//     "password":"ExamplePassword1!"
// }
// and returns a Json containing the error with this format:
// {
//     "AuthenticationResult": {
//         "AccessToken": "AccessTokenExample",
//         "ExpiresIn": 3600,
//         "IdToken": "IdTokenExample",
//         "NewDeviceMetadata": null,
//         "RefreshToken": "RefreshTokenExample",
//         "TokenType": "Bearer"
//     },
//     "ChallengeName": null,
//     "ChallengeParameters": {},
//     "Session": null
// }
func (a *App) Login(c echo.Context) (err error) {
	// r := new(Response)
	u := new(User)

	if err = c.Bind(u); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err = c.Validate(u); err != nil {
		return err
	}
	// if err = v.Struct(u.User); err != nil {
	// 	return err
	// }

	params := map[string]*string{
		"USERNAME": aws.String(u.Username),
		"PASSWORD": aws.String(u.Password),
	}

	secretHash := computeSecretHash(a.AppClientSecret, u.Username, a.AppClientID)
	params["SECRET_HASH"] = aws.String(secretHash)

	authTry := &cognito.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		AuthParameters: map[string]*string{
			"USERNAME":    aws.String(*params["USERNAME"]),
			"PASSWORD":    aws.String(*params["PASSWORD"]),
			"SECRET_HASH": aws.String(*params["SECRET_HASH"]),
		},
		ClientId: aws.String(a.AppClientID), // this is the app client ID
	}

	authResp, err := a.CognitoClient.InitiateAuth(authTry)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, authResp)
	}

	a.Token = *authResp.AuthenticationResult.AccessToken
	return c.JSON(http.StatusOK, authResp)
}

func (a *App) ForgotPassword(c echo.Context) (err error) {
	u := new(UserForgot)

	if err = c.Bind(u); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err = c.Validate(u); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	secretHash := computeSecretHash(a.AppClientSecret, u.Username, a.AppClientID)

	cognitoUser := &cognito.ForgotPasswordInput{
		SecretHash: aws.String(secretHash),
		ClientId:   aws.String(a.AppClientID),
		Username:   &u.Username,
	}

	cognitoUser.Validate()

	forgotPasswordOutput, err := a.CognitoClient.ForgotPassword(cognitoUser)

	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	return echo.NewHTTPError(http.StatusOK, forgotPasswordOutput)
}

func (a *App) ConfirmForgotPassword(c echo.Context, v validator.Validate) (err error) {

	u := new(UserConfirmationCode)

	if err = c.Bind(u); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err = c.Validate(u); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if err = v.Struct(u.User); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	secretHash := computeSecretHash(a.AppClientSecret, u.User.Username, a.AppClientID)

	cognitoUser := &cognito.ConfirmForgotPasswordInput{
		SecretHash:       aws.String(secretHash),
		ClientId:         aws.String(a.AppClientID),
		Username:         &u.User.Username,
		ConfirmationCode: &u.ConfirmationCode,
		Password:         &u.User.Password,
	}

	resp, err := a.CognitoClient.ConfirmForgotPassword(cognitoUser)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	return echo.NewHTTPError(http.StatusOK, resp)
}

func (a *App) Verify()

func computeSecretHash(clientSecret string, username string, clientId string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientId))

	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
