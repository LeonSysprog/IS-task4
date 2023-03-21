package main

import (
    "net/http"
    "github.com/gin-gonic/gin"
    "database/sql"
    "fmt"
    _"github.com/lib/pq"
    "crypto/rand"
    "crypto/sha256"
    "math/big"
    "encoding/hex"
    "strconv"
    "github.com/dgrijalva/jwt-go"
    "time"
)

const (
	host		= "127.0.0.1"
	port		= 5433
	dbuser		= "postgres"
	password	= "postgres"
	dbname		= "auth"
	secretKey	= "_987aBC_"
)

var authTokenString string
var userName	    string

type jsonUser struct {
    	User		string `json:"usr"`
    	Password	string `json:"pwd"`
}

func main() {
    	/* server launch */
    	router := gin.Default()
    	router.POST("/registrate", postRegistrate)
    	router.POST("/auth", postAuth)
    	router.POST("/refresh", postRefresh)
    	router.Run("localhost:8080")
    	/*****************/
}

func setupDB() *sql.DB {
	psqlConn := fmt.Sprintf("host = %s port = %d user = %s password = %s dbname = %s sslmode = disable", host, port, dbuser, password, dbname)

	db, err := sql.Open("postgres", psqlConn)
	checkError(err)
	
	return db
}

func cryptoRandInt() int64 {
	cryptoInt, err := rand.Int(rand.Reader, big.NewInt(100000))
	checkError(err)
	return cryptoInt.Int64()
}

func postRegistrate(c *gin.Context) {
	var newJsonUser jsonUser
	
    	if err := c.BindJSON(&newJsonUser); err != nil {
        	return
    	}

	salt := strconv.FormatInt(cryptoRandInt(), 10)
	
	hashFunction := sha256.New()
	passwordSalt := newJsonUser.Password + salt
	
	hashFunction.Write([]byte(passwordSalt))
	hashPasswordSalt := hex.EncodeToString(hashFunction.Sum(nil))
	
	db := setupDB()
	db.QueryRow("INSERT INTO users(\"name\", \"salt\", \"hash\") VALUES($1, $2, $3);", newJsonUser.User, salt, hashPasswordSalt)
	
    	c.IndentedJSON(http.StatusOK, newJsonUser)
}

func postAuth(c *gin.Context) {
	var authJsonUser jsonUser

    	if err := c.BindJSON(&authJsonUser); err != nil {
        	return
    	}
    
    	db := setupDB()
    	row := db.QueryRow("SELECT * FROM users WHERE name = $1;", authJsonUser.User)
    	fmt.Println(authJsonUser.User)
    
    	if row == nil {
    		c.IndentedJSON(http.StatusForbidden, authJsonUser)
    	}
    	
    	var id 	 int
    	var user string
    	var salt string
    	var hash string
    	
    	row.Scan(&id, &user, &salt, &hash)
    	
    	hashFunction := sha256.New()
    	passwordSalt := authJsonUser.Password + salt
	
	hashFunction.Write([]byte(passwordSalt))
	hashPasswordSalt := hex.EncodeToString(hashFunction.Sum(nil))
	
	if hash == hashPasswordSalt {
		tokenString := createToken(1)
		userName = user
		authTokenString = tokenString
		c.SetCookie("Access-Token", tokenString, 3660, "/", "", true, true)
		c.IndentedJSON(http.StatusOK, tokenString)
	} else {
		c.IndentedJSON(http.StatusForbidden, authJsonUser)
	}
}

func postRefresh(c *gin.Context) {
	var tokenString string
	
	if err := c.BindJSON(&tokenString); err != nil {
        	return
    	}
    
    	if tokenString == authTokenString {
    		c.SetCookie("Request-Token", tokenString, 3660, "/", "", true, true)
    	
    		tokenString := createToken(2)
    	
    		c.SetCookie("Access-Token", tokenString, 7320, "/", "", true, true)
		c.IndentedJSON(http.StatusOK, tokenString)
    	} else {
    		c.IndentedJSON(http.StatusForbidden, tokenString)
    	}
}

func createToken(hours time.Duration) string {
	claims := jwt.MapClaims{}
	claims["username"] = userName
	claims["exp"] = time.Now().Add(hours * time.Hour)
	claims["authorized"] = true
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secretKey))
	checkError(err)
	
	return tokenString
}

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}
