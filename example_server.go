package main

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	app := fiber.New(fiber.Config{
		AppName: "Dual Token Auth Service v2",
	})

	app.Use(logger.New())

	initRedis()
	if err := initSQLite(); err != nil {
		log.Printf("⚠️ SQLite initialization failed: %v", err)
	} else {
		if err := loadGJWTFromSQLite(); err != nil {
			log.Printf("⚠️ Failed to load GJWT from SQLite: %v", err)
		}
	}
	if redisClient != nil {
		go startCacheRefreshWorker()
	}

	setupFileServer(app)

	app.Get("/health", healthHandler)
	app.Post("/ljwt", createLJWTDirectHandler)
	app.Post("/auth", authHandler)
	app.Post("/register", registerHandler)

	protected := app.Group("/api", LJWTMiddleware())
	{
		protected.Get("/check", checkHandler)
		protected.Get("/gjwt/list", listGJWTHandler)
		protected.Get("/user/info", userInfoHandler)
	}

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString(`
			<h1>Dual Token Auth Service v2</h1>
			<p><strong>Упрощенная архитектура:</strong></p>
			<ul>
				<li><strong>GET /health</strong> - Проверка здоровья (публичный)</li>
				<li><strong>POST /ljwt</strong> - Создание LJWT (публичный)</li>
				<li><strong>GET /api/check</strong> - Тестовый endpoint (защищенный)</li>
				<li><strong>GET /api/gjwt/list</strong> - Список GJWT (защищенный)</li>
				<li><strong>GET /api/user/info</strong> - Информация пользователя (защищенный)</li>
			</ul>
			<p><em>Пользователю нужно хранить только LJWT!</em></p>
		`)
	})

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "3000"
	}

	log.Printf("🚀 Server starting on port %s", port)
	log.Printf("📊 Health check: http://localhost:%s/health", port)
	log.Printf("🔐 Protected API: http://localhost:%s/api/check", port)
	log.Printf("🎯 New LJWT endpoint: POST http://localhost:%s/ljwt", port)

	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func healthHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
		"redis":     redisClient != nil,
		"sqlite":    sqliteDB != nil,
		"service":   "Dual Token Auth v2",
		"version":   "2.0",
	})
}

func createLJWTDirectHandler(c *fiber.Ctx) error {
	var request struct {
		User   string `json:"user"`
		Device string `json:"device"`
	}

	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if request.User == "" || request.Device == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "User and device are required",
		})
	}

	gjwt := CreateGJWT(request.User, request.Device)
	if gjwt == "" {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create GJWT",
		})
	}

	clientIP := c.IP()
	country := c.Get("X-Country-Code", "unknown")
	exp := time.Now().Add(24 * time.Hour).Format(time.RFC3339)

	ljwt := CreateLJWT(clientIP, country, request.Device, exp, gjwt)
	if ljwt == "" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Failed to create LJWT - security policy violation",
		})
	}

	return c.JSON(fiber.Map{
		"ljwt":    ljwt,
		"user":    request.User,
		"device":  request.Device,
		"ip":      clientIP,
		"country": country,
		"expires": exp,
		"message": "LJWT created successfully. Store this token for future requests.",
	})
}

func checkHandler(c *fiber.Ctx) error {
	return c.JSON([]int{1, 2, 3})
}

func listGJWTHandler(c *fiber.Ctx) error {
	user := c.Locals(string(UserKey)).(string)

	if redisClient == nil {
		return c.JSON(fiber.Map{"tokens": []string{}})
	}

	var gjwtList []map[string]interface{}
	var cursor uint64

	for {
		var keys []string
		var err error
		pattern := fmt.Sprintf("gjwt:%s:*", user)
		keys, cursor, err = redisClient.Scan(ctx, cursor, pattern, 50).Result()
		if err != nil {
			break
		}

		for _, key := range keys {
			token, err := redisClient.Get(ctx, key).Result()
			if err != nil {
				continue
			}

			parts := strings.Split(key, ":")
			if len(parts) == 3 {
				device := parts[2]
				gjwtList = append(gjwtList, map[string]interface{}{
					"device": device,
					"token":  token,
				})
			}
		}

		if cursor == 0 {
			break
		}
	}

	return c.JSON(fiber.Map{
		"user":   user,
		"tokens": gjwtList,
		"count":  len(gjwtList),
	})
}

func userInfoHandler(c *fiber.Ctx) error {
	user := c.Locals(string(UserKey)).(string)
	device := c.Locals(string(DeviceKey)).(string)
	ip := c.Locals(string(IPKey)).(string)
	country := c.Locals(string(CountryKey)).(string)

	return c.JSON(fiber.Map{
		"user":      user,
		"device":    device,
		"ip":        ip,
		"country":   country,
		"timestamp": time.Now().Format(time.RFC3339),
		"session":   "active",
	})
}

func authHandler(c *fiber.Ctx) error {
	var request struct {
		User   string `json:"user"`
		Device string `json:"device"`
	}

	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if request.User == "" || request.Device == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "User and device are required",
		})
	}

	clientIP := c.IP()
	country := c.Get("X-Country-Code", "unknown")

	response, err := GetOrCreateLJWT(request.User, request.Device, clientIP, country)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(response)
}

func registerHandler(c *fiber.Ctx) error {
	var request struct {
		User     string `json:"user"`
		Device   string `json:"device"`
		Email    string `json:"email,omitempty"`
		Password string `json:"password,omitempty"`
	}

	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	clientIP := c.IP()
	country := c.Get("X-Country-Code", "unknown")

	response, err := GetOrCreateLJWT(request.User, request.Device, clientIP, country)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	response.Message = "Registration successful and LJWT issued"

	return c.JSON(response)
}

func setupFileServer(app *fiber.App) {
	if err := os.MkdirAll("./public/files", 0755); err != nil {
		log.Printf("Warning: Failed to create files directory: %v", err)
	}

	app.Static("/public", "./public")

	protectedFiles := app.Group("/secure-files", LJWTMiddleware())
	protectedFiles.Static("/secure-files", "./public/files")

	log.Println("📁 File server configured:")
	log.Println("   - Public files: /public")
	log.Println("   - Secure files: /secure-files (requires LJWT)")
}
