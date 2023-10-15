package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/stretchr/testify/require"
)

func Setup(ctx context.Context, assert *require.Assertions) interface{} {
	log.Println("Setup...")

	cfg := Config{
		ClientId:       "141uw2duh1es7upm46n0e44sku5qerpn",
		ClientSecret:   "gZ4L21GRMHOptnU2R2R4zvlvJ9TK4hZz",
		BoxSubjectType: "user",
		BoxSubjectId:   "385982796",
	}

	baseFolderId := "230813063542"

	accessToken := GetAccessToken(assert, cfg)
	folderId := CreateBaseFolder(assert, accessToken, baseFolderId)

	return map[string]string{
		"folderId":    folderId,
		"accessToken": accessToken,
	}
}

func Default(assert *require.Assertions, data interface{}) {
	// folderId, ok := data["folderId"].(string)
	log.Println("Found data", data)

	setupMap, ok := data.(map[string]interface{})
	log.Println("ok? ", ok)
	assert.True(ok, "primitive data type OK")

	folderId, folderIdFound := setupMap["folderId"]
	log.Println("Folder Id exists? ", folderIdFound)
	assert.True(folderIdFound, "Folder Id Exist?")
	log.Println("Found folderId: ", folderId)

	log.Println("Found acccessToken: ", setupMap["accessToken"])

	// log.Println("Found folder id: ", folderId)
}

type M map[string]interface{}

func HandleSummary(data M) (M, error) {
	bin, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, err
	}

	return M{
		"stdout": bin,
	}, nil
}

func GetFileInfo(filePath string, ctx context.Context) (string, string, int) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()
	log.Println("Go - Found file.Name(): ", file.Name())

	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println(err)
	}

	fileSize := int(fileInfo.Size())
	log.Println("Go - Found fileSize: ", fileSize)
	log.Println("Go - Found file name before format: ", fileInfo.Name())

	vu := ctx.Value("__VU").(int64)
	iter := ctx.Value("__ITER").(int64)

	fileName := fmt.Sprintf("%d.%d.%s", vu, iter, fileInfo.Name())
	log.Println("Found file name: ", fileName)

	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println(err)
	}
	h := sha1.New()
	h.Write(fileBytes)
	fileHash := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return fileName, fileHash, fileSize
}

func GetAccessToken(assert *require.Assertions, cfg Config) string {
	apiUrl := "https://api.box.com"
	resource := "/oauth2/token"
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", cfg.ClientId)
	data.Set("client_secret", cfg.ClientSecret)
	data.Set("box_subject_type", cfg.BoxSubjectType)
	data.Set("box_subject_id", cfg.BoxSubjectId)

	u, _ := url.ParseRequestURI(apiUrl)
	u.Path = resource
	urlStr := u.String()

	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodPost, urlStr, strings.NewReader(data.Encode()))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, _ := client.Do(r)
	fmt.Println(resp.Status)
	assert.Equal("200 OK", resp.Status, "Found access token")

	cl := resp.ContentLength
	bs := make([]byte, cl)
	resp.Body.Read(bs)
	// fmt.Println(string(bs))

	var boxAuth BoxAuth
	json.Unmarshal(bs, &boxAuth)

	return boxAuth.AccessToken
}

func CreateBaseFolder(assert *require.Assertions, accessToken string, baseFolderId string) string {
	fmt.Println("Found accessToken")
	apiUrl := "https://api.box.com"
	resource := "/2.0/folders"

	now := time.Now().Format("2006-01-02T15:04:05")
	parentFolderName := fmt.Sprintf("H1-ChunkedUpload-%s", now)
	createFolderReq := CreateFolderRequest{
		Name: parentFolderName,
		Parent: Parent{
			Id: baseFolderId,
		},
	}

	u, _ := url.ParseRequestURI(apiUrl)
	u.Path = resource
	urlStr := u.String()

	bs, _ := json.Marshal(createFolderReq)
	body := bytes.NewBuffer(bs)
	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodPost, urlStr, body)

	var token = "Bearer " + accessToken
	r.Header.Set("Authorization", token)
	r.Header.Set("Content-Type", "application/json")

	res, _ := client.Do(r)
	log.Println("Found status: ", res.Status)
	assert.Equal("201 Created", res.Status, "Created K6 test folder")

	resBody, error := io.ReadAll(res.Body)
	if error != nil {
		fmt.Println(error)
	}
	log.Println(string(resBody))

	var folder CreateFolderResponse
	json.Unmarshal(resBody, &folder)

	return folder.Id
}

type Config struct {
	ClientId       string `js:"clientId"`
	ClientSecret   string `js:"clientSecret"`
	BoxSubjectType string `js:"boxSubjectType"`
	BoxSubjectId   string `js:"boxSubjectId"`
}

type BoxAuth struct {
	AccessToken     string         `json:"access_token"`
	ExpiresIn       int            `json:"expires_in"`
	IssuedTokenType string         `json:"issued_token_type"`
	RefreshToken    string         `json:"refresh_token"`
	RestrictedTo    []RestrictedTo `json:"restricted_to"`
	TokenType       string         `json:"token_type"`
}

type RestrictedTo struct {
	Scope  string `json:"scope"`
	Object Object `json:"object"`
}

type Object struct {
	ID          string      `json:"id"`
	Etag        string      `json:"etag"`
	Type        string      `json:"type"`
	SequenceID  string      `json:"sequence_id"`
	Name        string      `json:"name"`
	Sha1        string      `json:"sha1"`
	FileVersion FileVersion `json:"file_version"`
}

type FileVersion struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Sha1 string `json:"sha1"`
}

type CreateFolderRequest struct {
	Name   string `json:"name"`
	Parent Parent `json:"parent"`
}

type Parent struct {
	Id string `json:"id"`
}

type CreateFolderResponse struct {
	Id   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}
