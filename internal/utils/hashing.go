package utils

import (
	"EverythingSuckz/fsb/config"
	"EverythingSuckz/fsb/internal/cache"
	"EverythingSuckz/fsb/internal/types"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func PackFile(fileName string, fileSize int64, mimeType string, fileID int64) string {
	return (&types.HashableFileStruct{FileName: fileName, FileSize: fileSize, MimeType: mimeType, FileID: fileID}).Pack()
}

func GetShortHash(fullHash string) string {
	return fullHash[:config.ValueOf.HashLength]
}

func BuildStreamToken(messageID int, file *types.File) (string, int64) {
	expiresAt := time.Now().Add(time.Duration(config.ValueOf.LinkTTLHours) * time.Hour).Unix()
	signature := signStreamPayload(messageID, file, expiresAt)
	return signature, expiresAt
}

func CheckStreamToken(messageID int, file *types.File, inputHash, expParam string) bool {
	expiresAt, err := strconv.ParseInt(expParam, 10, 64)
	if err != nil || expiresAt <= 0 {
		return false
	}

	tokenKey := activeTokenCacheKey(messageID, inputHash, expParam)
	if isTokenActive(tokenKey) {
		return true
	}

	if time.Now().Unix() > expiresAt {
		return false
	}

	expected := signStreamPayload(messageID, file, expiresAt)
	if !hmac.Equal([]byte(inputHash), []byte(expected)) {
		return false
	}

	activateToken(tokenKey)
	return true
}

func signStreamPayload(messageID int, file *types.File, expiresAt int64) string {
	payload := strings.Join([]string{
		"stream-v2",
		strconv.Itoa(messageID),
		strconv.FormatInt(file.ID, 10),
		strconv.FormatInt(file.FileSize, 10),
		file.MimeType,
		file.FileName,
		strconv.FormatInt(expiresAt, 10),
	}, "|")

	mac := hmac.New(sha256.New, []byte(config.ValueOf.HashSecret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func activeTokenCacheKey(messageID int, inputHash, expParam string) string {
	return fmt.Sprintf("streamtoken:%d:%s:%s", messageID, expParam, inputHash)
}

func isTokenActive(key string) bool {
	_, err := cache.GetCache().GetBytes(key)
	return err == nil
}

func activateToken(key string) bool {
	err := cache.GetCache().SetBytes(
		key,
		[]byte{1},
		config.ValueOf.LinkGraceHours*3600,
	)
	return err == nil
}
