# Multi-stage build для CGO
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Установка зависимостей включая C-компилятор
RUN apk add --no-cache sqlite-dev gcc musl-dev git

# Копирование зависимостей
COPY go.mod go.sum ./
RUN go mod download

# Копирование исходного кода
COPY *.go ./

# Сборка с CGO_ENABLED=1
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o dtap .

# Финальный образ
FROM alpine:latest

WORKDIR /app

# Установка SQLite в runtime
RUN apk add --no-cache sqlite

# Копируем бинарник из builder stage
COPY --from=builder /app/dtap .

# Создание папок для данных
RUN mkdir -p /app/data /app/public/files

VOLUME /app/data

EXPOSE 3000

CMD ["./dtap"]