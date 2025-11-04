package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	_ "github.com/mattn/go-sqlite3"
)

const GJWT_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkdKV1QifQ"

var (
	JWT_SECRET_KEY = os.Getenv("JWT_SECRET_KEY")
	GJWT_TTL       = getEnvDuration("GJWT_TTL", 24*time.Hour)
	IP_CHECK_TTL   = getEnvDuration("IP_CHECK_TTL", 10*time.Minute)
	REISSUE_IP_TTL = getEnvDuration("REISSUE_IP_TTL", 1*time.Hour)
	SYNC_INTERVAL  = getEnvDuration("SYNC_INTERVAL", 5*time.Minute)
)

var (
	redisClient *redis.Client
	sqliteDB    *sql.DB
	ctx         = context.Background()
)

type LJWTResponse struct {
	LJWT    string    `json:"ljwt"`
	User    string    `json:"user"`
	Device  string    `json:"device"`
	IsNew   bool      `json:"is_new"`
	Expires time.Time `json:"expires"`
	Message string    `json:"message"`
}

type GJWTCache struct {
	dataPtr *sync.Map
}

var (
	gjwtCache  = &GJWTCache{dataPtr: &sync.Map{}}
	cacheMutex sync.RWMutex
)

type GJWTData struct {
	Token     string
	User      string
	Device    string
	IPs       []string
	Country   string
	ExpiresAt time.Time
}

func startCacheRefreshWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		refreshCacheFromRedis()
	}
}

func refreshCacheFromRedis() {
	if redisClient == nil {
		return
	}

	log.Println("🔄 Starting cache refresh from Redis...")

	newCache := &sync.Map{}

	keys, err := redisClient.Keys(ctx, "gjwt:*").Result()
	if err != nil {
		log.Printf("❌ Error getting keys for cache refresh: %v", err)
		return
	}

	var loadedCount int
	for _, key := range keys {
		token, err := redisClient.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		parts := strings.Split(key, ":")
		if len(parts) != 3 {
			continue
		}

		user := parts[1]
		device := parts[2]
		cacheKey := user + ":" + device

		ttl, err := redisClient.TTL(ctx, key).Result()
		if err != nil {
			continue
		}

		newCache.Store(cacheKey, GJWTData{
			Token:     token,
			User:      user,
			Device:    device,
			ExpiresAt: time.Now().Add(ttl),
		})
		loadedCount++
	}

	cacheMutex.Lock()
	gjwtCache.dataPtr = newCache
	cacheMutex.Unlock()

	log.Printf("✅ Cache refreshed: %d entries loaded", loadedCount)
}

type ReissueRecord struct {
	Timestamp string `json:"timestamp"`
	Reason    string `json:"reason"`
}

type ContextKey string

const (
	UserKey    ContextKey = "user"
	DeviceKey  ContextKey = "device"
	IPKey      ContextKey = "ip"
	CountryKey ContextKey = "country"
)

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			return duration
		}
	}
	return defaultVal
}

func initRedis() {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:         redisURL,
		Password:     os.Getenv("REDIS_PASSWORD"),
		DB:           0,
		PoolSize:     100,
		MinIdleConns: 10,
		MaxRetries:   3,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		PoolTimeout:  2 * time.Second,
	})

	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		fmt.Printf("Warning: Failed to connect to Redis: %v\n", err)
		fmt.Println("Continuing without Redis...")
	}
}

func initSQLite() error {
	dbPath := os.Getenv("SQLITE_PATH")
	if dbPath == "" {
		dbPath = "./gjwt_data.db"
	}

	var err error
	sqliteDB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open SQLite database: %v", err)
	}

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS gjwt_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL,
		device_id TEXT NOT NULL,
		token TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		UNIQUE(user_id, device_id)
	);
	
	CREATE INDEX IF NOT EXISTS idx_user_device ON gjwt_tokens(user_id, device_id);
	CREATE INDEX IF NOT EXISTS idx_expires_at ON gjwt_tokens(expires_at);
	`

	_, err = sqliteDB.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	return nil
}

func startSyncWorker() {
	ticker := time.NewTicker(SYNC_INTERVAL)
	defer ticker.Stop()

	for range ticker.C {
		syncGJWTToSQLite()
	}
}

func syncGJWTToSQLite() {
	if redisClient == nil || sqliteDB == nil {
		return
	}

	keys, err := redisClient.Keys(ctx, "gjwt:*").Result()
	if err != nil {
		log.Printf("Error getting GJWT keys from Redis: %v", err)
		return
	}

	for _, key := range keys {
		token, err := redisClient.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		parts := strings.Split(key, ":")
		if len(parts) != 3 {
			continue
		}

		user := parts[1]
		device := parts[2]

		ttl, err := redisClient.TTL(ctx, key).Result()
		if err != nil {
			continue
		}

		expiresAt := time.Now().Add(ttl)

		_, err = sqliteDB.Exec(`
			INSERT OR REPLACE INTO gjwt_tokens (user_id, device_id, token, expires_at) 
			VALUES (?, ?, ?, ?)
		`, user, device, token, expiresAt)

		if err != nil {
			log.Printf("Error storing GJWT in SQLite: %v", err)
		}
	}

	log.Printf("Synced %d GJWT tokens to SQLite", len(keys))
}

func loadGJWTFromSQLite() error {
	if sqliteDB == nil {
		return fmt.Errorf("SQLite not initialized")
	}

	rows, err := sqliteDB.Query(`
		SELECT user_id, device_id, token, expires_at 
		FROM gjwt_tokens 
		WHERE expires_at > datetime('now')
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var loadedCount int
	for rows.Next() {
		var user, device, token string
		var expiresAt time.Time

		err := rows.Scan(&user, &device, &token, &expiresAt)
		if err != nil {
			log.Printf("Error scanning GJWT row: %v", err)
			continue
		}

		cacheKey := user + ":" + device
		gjwtCache.set(cacheKey, token, time.Until(expiresAt))

		if redisClient != nil {
			key := fmt.Sprintf("gjwt:%s:%s", user, device)
			redisClient.Set(ctx, key, token, time.Until(expiresAt))
		}

		loadedCount++
	}

	log.Printf("Loaded %d GJWT tokens from SQLite", loadedCount)
	return nil
}

func GetOrCreateLJWT(user, device, clientIP, country string) (*LJWTResponse, error) {
	log.Printf("🎯 GetOrCreateLJWT: user=%s, device=%s", user, device)

	existingGJWT, err := findExistingGJWT(user, device)
	if err != nil {
		return nil, fmt.Errorf("error finding GJWT: %v", err)
	}

	var gjwt string
	var isNew bool

	if existingGJWT != "" {
		log.Printf("🔍 Using existing GJWT for user=%s, device=%s", user, device)
		gjwt = existingGJWT
		isNew = false
	} else {
		log.Printf("🆕 Creating new GJWT for user=%s, device=%s", user, device)
		gjwt = CreateGJWT(user, device)
		if gjwt == "" {
			return nil, fmt.Errorf("failed to create GJWT")
		}
		isNew = true
	}

	exp := time.Now().Add(24 * time.Hour)
	ljwt := CreateLJWT(clientIP, country, device, exp.Format(time.RFC3339), gjwt)
	if ljwt == "" {
		return nil, fmt.Errorf("failed to create LJWT")
	}

	response := &LJWTResponse{
		LJWT:    ljwt,
		User:    user,
		Device:  device,
		IsNew:   isNew,
		Expires: exp,
		Message: "LJWT created successfully",
	}

	if isNew {
		response.Message = "New GJWT created and LJWT issued"
	} else {
		response.Message = "LJWT reissued using existing GJWT"
	}

	log.Printf("✅ GetOrCreateLJWT success: user=%s, isNew=%v", user, isNew)
	return response, nil
}

func findExistingGJWT(user, device string) (string, error) {
	cacheKey := user + ":" + device

	if cached := gjwtCache.get(cacheKey); cached != "" {
		log.Printf("🔍 Found GJWT in cache for user=%s", user)
		return cached, nil
	}

	if redisClient != nil {
		key := fmt.Sprintf("gjwt:%s:%s", user, device)
		storedGJWT, err := redisClient.Get(ctx, key).Result()
		if err == nil && storedGJWT != "" {
			log.Printf("🔍 Found GJWT in Redis for user=%s", user)
			gjwtCache.set(cacheKey, storedGJWT, GJWT_TTL)
			return storedGJWT, nil
		}
	}

	if sqliteDB != nil {
		var token string
		var expiresAt time.Time

		err := sqliteDB.QueryRow(`
					SELECT token, expires_at 
					FROM gjwt_tokens 
					WHERE user_id = ? AND device_id = ? AND expires_at > datetime('now')
			`, user, device).Scan(&token, &expiresAt)

		if err == nil && token != "" {
			log.Printf("🔍 Found GJWT in SQLite for user=%s", user)
			gjwtCache.set(cacheKey, token, time.Until(expiresAt))
			if redisClient != nil {
				redisClient.Set(ctx, fmt.Sprintf("gjwt:%s:%s", user, device), token, time.Until(expiresAt))
			}
			return token, nil
		}
	}

	log.Printf("🔍 No existing GJWT found for user=%s, device=%s", user, device)
	return "", nil
}

func CreateGJWT(user string, device string) string {
	cacheKey := user + ":" + device
	if cached := gjwtCache.get(cacheKey); cached != "" {
		return cached
	}

	payload := generatePayloadGJWT(user, device)
	signature := generateGJWTsignature(payload)
	token := GJWT_HEADER + "." + payload + "." + signature

	if redisClient != nil {
		key := fmt.Sprintf("gjwt:%s:%s", user, device)
		err := redisClient.Set(ctx, key, token, GJWT_TTL).Err()
		if err != nil {
			fmt.Printf("Error storing GJWT in Redis: %v\n", err)
		}
	}

	gjwtCache.set(cacheKey, token, GJWT_TTL)
	return token
}

func CreateLJWT(ip string, country string, device string, exp string, GJWT string) string {
	gjwtDevice, err := getDeviceFromGJWT(GJWT)
	if err != nil || gjwtDevice != device {
		fmt.Printf("Device change detected: %s -> %s. Removing GJWT.\n", gjwtDevice, device)
		RemoveGJWTFromStorage(GJWT)
		return ""
	}

	if !VerifyGJWTInStorage(GJWT) {
		fmt.Printf("GJWT not found in storage. Cannot create LJWT.\n")
		return ""
	}

	user, deviceFromGJWT, err := extractUserDeviceFromGJWT(GJWT)
	if err != nil {
		return ""
	}

	if redisClient != nil {
		pipe := redisClient.Pipeline()

		key := fmt.Sprintf("gjwt:%s:%s", user, deviceFromGJWT)
		ipKey := fmt.Sprintf("gjwt_ip:%s", GJWT)
		countryKey := fmt.Sprintf("gjwt_country:%s", GJWT)

		pipe.Expire(ctx, key, GJWT_TTL)

		storedIPCmd := pipe.Get(ctx, ipKey)
		storedCountryCmd := pipe.Get(ctx, countryKey)

		_, execErr := pipe.Exec(ctx)
		if execErr != nil && execErr != redis.Nil {
			fmt.Printf("Redis pipeline error: %v\n", execErr)
		}

		storedIP, _ := storedIPCmd.Result()
		storedCountry, _ := storedCountryCmd.Result()

		if storedIP != "" {
			if storedCountry != "" && storedCountry != country {
				fmt.Printf("Country change detected: %s -> %s. Removing GJWT.\n", storedCountry, country)
				RemoveGJWTFromStorage(GJWT)
				return ""
			}

			if storedIP != ip {
				fmt.Printf("Third IP detected: stored=%s, new=%s. Removing GJWT.\n", storedIP, ip)
				RemoveGJWTFromStorage(GJWT)
				return ""
			}

			if storedCountry != country {
				redisClient.Set(ctx, countryKey, country, GJWT_TTL)
			}
		} else {
			if storedCountry != "" && storedCountry != country {
				fmt.Printf("Country change detected: %s -> %s. Removing GJWT.\n", storedCountry, country)
				RemoveGJWTFromStorage(GJWT)
				return ""
			}

			pipe = redisClient.Pipeline()
			pipe.Set(ctx, countryKey, country, GJWT_TTL)
			pipe.Set(ctx, ipKey, ip, IP_CHECK_TTL)
			pipe.Exec(ctx)
		}
	}

	payload := generatePayloadLJWT(ip, country, exp)
	signature := generateLJWTsignature(payload, GJWT)
	header := generateLJWTheader(GJWT)
	return header + "." + payload + "." + signature
}

func VerifyLJWT(token string, currentIP string, currentDevice string, currentCountry string) string {
	log.Printf("🔐 Starting LJWT verification...")

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		log.Printf("❌ Invalid token format: expected 3 parts, got %d", len(parts))
		return CreateNewLJWT("", "", "", "Invalid token format", currentIP, currentDevice, currentCountry)
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		log.Printf("❌ Failed to decode header: %v", err)
		return CreateNewLJWT("", "", "", "Invalid header encoding", currentIP, currentDevice, currentCountry)
	}

	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		log.Printf("❌ Failed to unmarshal header: %v", err)
		return CreateNewLJWT("", "", "", "Invalid header JSON", currentIP, currentDevice, currentCountry)
	}

	gjwt, exists := header["gjt"]
	if !exists {
		log.Printf("❌ GJWT not found in LJWT header")
		return CreateNewLJWT("", "", "", "GJWT not found in header", currentIP, currentDevice, currentCountry)
	}

	log.Printf("🔍 Extracted GJWT from LJWT: %s...", gjwt[:20])

	gjwtDevice, err := getDeviceFromGJWT(gjwt)
	if err != nil {
		log.Printf("❌ Failed to get device from GJWT: %v", err)
		RemoveGJWTFromStorage(gjwt)
		return ""
	}

	if gjwtDevice != currentDevice {
		log.Printf("❌ Device mismatch: GJWT device=%s, current device=%s", gjwtDevice, currentDevice)
		RemoveGJWTFromStorage(gjwt)
		return ""
	}

	if !VerifyGJWTInStorage(gjwt) {
		log.Printf("❌ GJWT not found in storage")
		return CreateNewLJWT("", "", "", "GJWT not found in storage", currentIP, currentDevice, currentCountry)
	}

	dataToVerify := parts[0] + "." + parts[1]
	receivedSignature := parts[2]

	mac := hmac.New(sha256.New, []byte(gjwt))
	mac.Write([]byte(dataToVerify))
	expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expectedSignature), []byte(receivedSignature)) {
		log.Printf("❌ Invalid signature")
		return CreateNewLJWT("", "", "", "Invalid signature", currentIP, currentDevice, currentCountry)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Printf("❌ Failed to decode payload: %v", err)
		return CreateNewLJWT("", "", "", "Invalid payload encoding", currentIP, currentDevice, currentCountry)
	}

	var payload map[string]string
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		log.Printf("❌ Failed to unmarshal payload: %v", err)
		return CreateNewLJWT("", "", "", "Invalid payload JSON", currentIP, currentDevice, currentCountry)
	}

	countryInToken := payload["cnt"]
	if countryInToken != currentCountry {
		log.Printf("❌ Country changed: token=%s, current=%s", countryInToken, currentCountry)
		return ""
	}

	exp, exists := payload["exp"]
	if !exists {
		log.Printf("❌ EXP not found in payload")
		return CreateNewLJWT("", "", "", "EXP not found", currentIP, currentDevice, currentCountry)
	}

	if !checkExpiration(exp) {
		log.Printf("🔄 Token expired, attempting reissue...")
		ip := payload["ip"]
		country := payload["cnt"]

		if redisClient != nil {
			reissueIPKey := fmt.Sprintf("reissue_ip:%s", gjwt)
			storedIP, err := redisClient.Get(ctx, reissueIPKey).Result()

			if err == nil && storedIP != "" && storedIP != currentIP {
				log.Printf("🚨 Suspicious reissue: IP changed from %s to %s", storedIP, currentIP)
				RemoveGJWTFromStorage(gjwt)
				return ""
			}

			redisClient.Set(ctx, reissueIPKey, currentIP, REISSUE_IP_TTL)
		}

		return CreateNewLJWT(ip, country, gjwt, "Token expired", currentIP, currentDevice, currentCountry)
	}

	log.Printf("✅ LJWT verification successful")
	return gjwt
}

func CreateNewLJWT(ip, country, gjwt, reason, currentIP, currentDevice, currentCountry string) string {
	if ip == "" {
		ip = currentIP
	}
	if country == "" {
		country = currentCountry
	}
	if gjwt == "" {
		return ""
	}

	newExp := time.Now().Add(24 * time.Hour).Format(time.RFC3339)

	if reason != "" && redisClient != nil {
		record := ReissueRecord{
			Timestamp: time.Now().Format(time.RFC3339),
			Reason:    reason,
		}
		historyKey := fmt.Sprintf("reissue_history:%s", gjwt)
		historyJSON, _ := json.Marshal(record)
		redisClient.RPush(ctx, historyKey, historyJSON)
		redisClient.Expire(ctx, historyKey, 7*24*time.Hour)
	}

	return CreateLJWT(ip, country, currentDevice, newExp, gjwt)
}

func extractUserDeviceFromGJWT(gjwt string) (string, string, error) {
	log.Printf("🔍 Starting GJWT extraction: %s...", gjwt[:50])

	parts := strings.Split(gjwt, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid GJWT format: expected 3 parts, got %d", len(parts))
	}

	payloadPart := parts[1]
	log.Printf("🔍 GJWT payload part: %s", payloadPart)

	switch len(payloadPart) % 4 {
	case 2:
		payloadPart += "=="
	case 3:
		payloadPart += "="
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		log.Printf("❌ Failed to decode payload: %v", err)
		payloadJSON, err = base64.StdEncoding.DecodeString(payloadPart)
		if err != nil {
			return "", "", fmt.Errorf("failed to decode payload with both methods: %v", err)
		}
	}

	log.Printf("🔍 GJWT Payload JSON: %s", string(payloadJSON))

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	log.Printf("🔍 GJWT Payload fields: %+v", payload)

	user, userOk := payload["sub"].(string)
	if !userOk {
		user, userOk = payload["user"].(string)
		log.Printf("🔍 Trying 'user' field: %s (ok: %v)", user, userOk)
	}

	device, deviceOk := payload["dvc"].(string)
	if !deviceOk {
		device, deviceOk = payload["device"].(string)
		log.Printf("🔍 Trying 'device' field: %s (ok: %v)", device, deviceOk)
	}

	if !userOk || !deviceOk {
		return "", "", fmt.Errorf("missing user or device in GJWT payload. Fields found: %v", getMapKeys(payload))
	}

	log.Printf("✅ Successfully extracted: User=%s, Device=%s", user, device)
	return user, device, nil
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func getDeviceFromGJWT(gjwt string) (string, error) {
	_, device, err := extractUserDeviceFromGJWT(gjwt)
	return device, err
}

func VerifyGJWTInStorage(gjwt string) bool {
	if !VerifyGJWT(gjwt) {
		return false
	}

	if redisClient == nil {
		return true
	}

	user, device, err := extractUserDeviceFromGJWT(gjwt)
	if err != nil {
		return false
	}

	cacheKey := user + ":" + device
	if cached := gjwtCache.get(cacheKey); cached == gjwt {
		return true
	}

	key := fmt.Sprintf("gjwt:%s:%s", user, device)
	storedGJWT, err := redisClient.Get(ctx, key).Result()
	if err != nil {
		return false
	}

	if storedGJWT == gjwt {
		gjwtCache.set(cacheKey, gjwt, GJWT_TTL)
	}

	return storedGJWT == gjwt
}

func (c *GJWTCache) get(key string) string {
	cacheMutex.RLock()
	currentCache := c.dataPtr
	cacheMutex.RUnlock()

	if data, exists := currentCache.Load(key); exists {
		gjwtData := data.(GJWTData)
		if time.Now().Before(gjwtData.ExpiresAt) {
			return gjwtData.Token
		}
		currentCache.Delete(key)
	}
	return ""
}

func (c *GJWTCache) set(key, token string, ttl time.Duration) {
	cacheMutex.RLock()
	currentCache := c.dataPtr
	cacheMutex.RUnlock()

	currentCache.Store(key, GJWTData{
		Token:     token,
		ExpiresAt: time.Now().Add(ttl),
	})
}

func (c *GJWTCache) remove(key string) {
	cacheMutex.RLock()
	currentCache := c.dataPtr
	cacheMutex.RUnlock()

	currentCache.Delete(key)
}

func RemoveGJWTFromStorage(gjwt string) {
	if redisClient == nil {
		return
	}

	user, device, err := extractUserDeviceFromGJWT(gjwt)
	if err != nil {
		return
	}

	cacheKey := user + ":" + device
	gjwtCache.remove(cacheKey)

	pipe := redisClient.Pipeline()

	key := fmt.Sprintf("gjwt:%s:%s", user, device)
	ipKey := fmt.Sprintf("gjwt_ip:%s", gjwt)
	reissueIPKey := fmt.Sprintf("reissue_ip:%s", gjwt)
	countryKey := fmt.Sprintf("gjwt_country:%s", gjwt)

	pipe.Del(ctx, key, ipKey, reissueIPKey, countryKey)
	pipe.Exec(ctx)
}

func GetReissueHistory(gjwt string) []ReissueRecord {
	if redisClient != nil {
		return nil
	}

	historyKey := fmt.Sprintf("reissue_history:%s", gjwt)
	results, err := redisClient.LRange(ctx, historyKey, 0, -1).Result()
	if err != nil {
		return nil
	}

	var history []ReissueRecord
	for _, result := range results {
		var record ReissueRecord
		if err := json.Unmarshal([]byte(result), &record); err == nil {
			history = append(history, record)
		}
	}
	return history
}

func checkExpiration(exp string) bool {
	expTime, err := time.Parse(time.RFC3339, exp)
	if err != nil {
		return false
	}
	return time.Now().Before(expTime)
}

func generateGJWTsignature(payload string) string {
	dataToSign := GJWT_HEADER + "." + payload
	return HS256Base64(dataToSign, JWT_SECRET_KEY)
}

func generateLJWTsignature(payload string, GJWT string) string {
	header := generateLJWTheader(GJWT)
	dataToSign := header + "." + payload
	return HS256Base64(dataToSign, GJWT)
}

func generatePayloadGJWT(user string, device string) string {
	payload := map[string]string{
		"sub": user,
		"dvc": device,
	}
	payloadJSON, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(payloadJSON)
}

func generatePayloadLJWT(ip string, country string, exp string) string {
	payload := map[string]string{
		"ip":  ip,
		"cnt": country,
		"exp": exp,
	}
	payloadJSON, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(payloadJSON)
}

func generateLJWTheader(GJWT string) string {
	header := map[string]string{
		"alg": "HS256",
		"typ": "LJWT",
		"gjt": GJWT,
	}
	headerJSON, _ := json.Marshal(header)
	return base64.RawURLEncoding.EncodeToString(headerJSON)
}

func VerifyGJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	dataToVerify := parts[0] + "." + parts[1]
	receivedSignature := parts[2]

	if parts[0] != GJWT_HEADER {
		return false
	}

	mac := hmac.New(sha256.New, []byte(JWT_SECRET_KEY))
	mac.Write([]byte(dataToVerify))
	expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expectedSignature), []byte(receivedSignature))
}

func HS256(data string) string {
	key := JWT_SECRET_KEY
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func HS256Base64(data string, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
