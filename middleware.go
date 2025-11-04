package main

import (
	"github.com/gofiber/fiber/v2"
	"log"
	"strings"
	//"time" for example handler
)

func DebugMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		log.Printf("🔍 Incoming request: %s %s", c.Method(), c.Path())
		log.Printf("🔍 Headers: Authorization=%s, X-Device-ID=%s, X-Country-Code=%s",
			c.Get("Authorization"), c.Get("X-Device-ID"), c.Get("X-Country-Code"))
		return c.Next()
	}
}

func LJWTMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			log.Printf("❌ No authorization header")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authorization header required",
			})
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Printf("❌ Invalid authorization format: %s", authHeader)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid authorization format. Use: Bearer <token>",
			})
		}

		token := parts[1]
		clientIP := c.IP()
		device := c.Get("X-Device-ID", "unknown")
		country := c.Get("X-Country-Code", "unknown")

		log.Printf("🔐 Verifying LJWT: IP=%s, Device=%s, Country=%s", clientIP, device, country)

		verifiedToken := VerifyLJWT(token, clientIP, device, country)
		if verifiedToken == "" {
			log.Printf("❌ LJWT verification failed")
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Invalid or expired token",
			})
		}

		log.Printf("🔍 Extracting user/device from verified token...")
		user, deviceFromToken, err := extractUserDeviceFromGJWT(verifiedToken)
		if err != nil {
			log.Printf("❌ Failed to extract user/device from GJWT: %v", err)
			log.Printf("❌ Verified token: %s", verifiedToken)
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Invalid token data: " + err.Error(),
			})
		}

		log.Printf("✅ LJWT verified successfully: User=%s, Device=%s", user, deviceFromToken)

		c.Locals(string(UserKey), user)
		c.Locals(string(DeviceKey), deviceFromToken)
		c.Locals(string(IPKey), clientIP)
		c.Locals(string(CountryKey), country)

		return c.Next()
	}
}

//
//func ProtectedHandler(c *fiber.Ctx) error {
//	user := c.Locals(string(UserKey)).(string)
//	device := c.Locals(string(DeviceKey)).(string)
//	ip := c.Locals(string(IPKey)).(string)
//	country := c.Locals(string(CountryKey)).(string)
//
//	return c.JSON(fiber.Map{
//		"message":   "Access granted to protected resource",
//		"user":      user,
//		"device":    device,
//		"ip":        ip,
//		"country":   country,
//		"timestamp": time.Now().Format(time.RFC3339),
//	})
//}

//  обработчик для создания LJWT
//func CreateLJWTHandler(c *fiber.Ctx) error {
//	var request struct {
//		GJWT   string `json:"gjwt"`
//		Device string `json:"device"`
//		Exp    string `json:"exp,omitempty"`
//	}
//
//	if err := c.BodyParser(&request); err != nil {
//		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
//			"error": "Invalid request body",
//		})
//	}
//
//	if request.GJWT == "" {
//		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
//			"error": "GJWT is required",
//		})
//	}
//
//	clientIP := c.IP()
//	country := c.Get("X-Country-Code", "unknown")
//	device := request.Device
//
//	if request.Exp == "" {
//		request.Exp = time.Now().Add(24 * time.Hour).Format(time.RFC3339)
//	}
//
//	ljwt := CreateLJWT(clientIP, country, device, request.Exp, request.GJWT)
//	if ljwt == "" {
//		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
//			"error": "Failed to create LJWT - possible security violation",
//		})
//	}
//
//	return c.JSON(fiber.Map{
//		"ljwt":    ljwt,
//		"ip":      clientIP,
//		"country": country,
//		"expires": request.Exp,
//	})
//}
