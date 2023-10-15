package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stretchr/testify/assert"
)

func Setup(ctx context.Context, assert assert.Assertions) interface{} {
	log.Println("Setup...")

	cfg := Config{
		ClientId:       "141uw2duh1es7upm46n0e44sku5qerpn",
		ClientSecret:   "gZ4L21GRMHOptnU2R2R4zvlvJ9TK4hZz",
		BoxSubjectType: "user",
		BoxSubjectId:   "385982796",
	}

	baseFolderId := "230813063542"

	// env := ctx.Value("__ENV").(map[string]string)
	// filePath := env["FILE_PATH"]
	// log.Println("Found filePath: ", filePath)
	// log.Println("Did we find a file path? ", filePathFound)

	accessToken := GetAccessToken(assert, cfg)
	folderId := CreateBaseFolder(assert, accessToken, baseFolderId)

	return map[string]string{
		"folderId":    folderId,
		"accessToken": accessToken,
		// "filePath":    filePath,
	}
}

func Default(ctx context.Context, assert assert.Assertions, data interface{}) {
	// folderId, ok := data["folderId"].(string)
	log.Println("Found data", data)

	setupMap, ok := data.(map[string]interface{})
	log.Println("ok? ", ok)
	assert.True(ok, "Did map from Setup pass to Default?")

	folderId, folderIdFound := setupMap["folderId"]
	log.Println("Found folderId: ", folderId)
	assert.True(folderIdFound, "Does Folder Id Exist?")

	accessToken, accessTokenFound := setupMap["accessToken"]
	log.Println("Found acccessToken: ", accessToken)
	assert.True(accessTokenFound, "Does Access Token Exist?")

	// filePath, filePathFound := setupMap["filePath"].(string)
	// log.Println("Found filePath: ", filePath)
	// assert.True(filePathFound, "Does File Path Exist?")

	// fileName, fileHash, fileSize := GetFileInfo(filePath, ctx)
	// log.Printf("Found fileName: %s, fileHash: %s, fileSize: %d", fileName, fileHash, fileSize)

	// log.Println("Found folder id: ", folderId)
}

func GetAccessToken(assert assert.Assertions, cfg Config) string {
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

func CreateBaseFolder(assert assert.Assertions, accessToken string, baseFolderId string) string {
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

// func GetFileInfo(filePath string, ctx context.Context) (string, string, int) {
// 	file, err := os.Open(filePath)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	defer file.Close()
// 	log.Println("Go - Found file.Name(): ", file.Name())

// 	fileInfo, err := file.Stat()
// 	if err != nil {
// 		fmt.Println(err)
// 	}

// 	fileSize := int(fileInfo.Size())
// 	log.Println("Go - Found fileSize: ", fileSize)
// 	log.Println("Go - Found file name before format: ", fileInfo.Name())

// 	vu := ctx.Value("__VU").(int64)
// 	iter := ctx.Value("__ITER").(int64)

// 	fileName := fmt.Sprintf("%d.%d.%s", vu, iter, fileInfo.Name())
// 	log.Println("Found file name: ", fileName)

// 	fileBytes, err := os.ReadFile(filePath)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	h := sha1.New()
// 	h.Write(fileBytes)
// 	fileHash := base64.URLEncoding.EncodeToString(h.Sum(nil))

// 	return fileName, fileHash, fileSize
// }

// func CreateUploadSession(fileName string, fileSize int, folderId string, accessToken string) CreateUploadSessionResponse {
// 	log.Printf("Go - Found accessToken: %v", accessToken)

// 	cusr := CreateUploadSessionRequest{
// 		FileName: fileName,
// 		FileSize: fileSize,
// 		FolderId: folderId,
// 	}
// 	log.Printf("Go - Found cusr: %+v", cusr)

// 	apiUrl := "https://upload.box.com"
// 	resource := "/api/2.0/files/upload_sessions"

// 	u, _ := url.ParseRequestURI(apiUrl)
// 	u.Path = resource
// 	urlStr := u.String()

// 	bs, _ := json.Marshal(cusr)
// 	body := bytes.NewBuffer(bs)
// 	client := &http.Client{}
// 	r, _ := http.NewRequest(http.MethodPost, urlStr, body)
// 	var token = "Bearer " + accessToken
// 	r.Header.Set("Authorization", token)
// 	r.Header.Set("Content-Type", "application/json")

// 	res, _ := client.Do(r)
// 	log.Println("Found status: ", res.Status)
// 	resBody, error := io.ReadAll(res.Body)
// 	if error != nil {
// 		fmt.Println(error)
// 	}
// 	log.Println(string(resBody))

// 	var usr CreateUploadSessionResponse
// 	json.Unmarshal(resBody, &usr)
// 	return usr
// }

// func UploadParts(usr CreateUploadSessionResponse, filePath string, fileSize int, accessToken string) []Part {
// 	var wg sync.WaitGroup

// 	totalParts := usr.TotalParts
// 	partSize := usr.PartSize
// 	chunksizes := make([]Chunk, totalParts)
// 	processed := 0

// 	file, err := os.Open(filePath)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	defer file.Close()

// 	for i := 0; i < totalParts; i++ {
// 		byteDiff := fileSize - processed
// 		fmt.Printf("Found byte diff: %v, fileSize: %v, processBytes: %v", byteDiff, fileSize, processed)

// 		if byteDiff < partSize {
// 			fmt.Println("Found smaller diff: ", byteDiff)
// 			chunksizes[i].bufsize = byteDiff
// 		} else {
// 			chunksizes[i].bufsize = partSize
// 		}
// 		chunksizes[i].offset = int64(partSize * i)

// 		fmt.Printf("Found chunksizes: %v", chunksizes[i])
// 		fmt.Println("")
// 		processed += partSize
// 	}

// 	wg.Add(totalParts)
// 	uploadedParts := []Part{}
// 	for i := 0; i < totalParts; i++ {
// 		partchan := make(chan Part)

// 		chunk := chunksizes[i]
// 		buffer := make([]byte, chunk.bufsize)
// 		_, err := file.ReadAt(buffer, chunk.offset)

// 		if err != nil && err != io.EOF {
// 			fmt.Println(err)
// 		}

// 		h := sha1.New()
// 		h.Write(buffer)
// 		sha1_hash := base64.URLEncoding.EncodeToString(h.Sum(nil))

// 		go UploadSinglePart(wg, usr, accessToken, sha1_hash, chunk, fileSize, buffer, partchan)
// 		part := <-partchan
// 		fmt.Println("Found part chan return: %+v", part)

// 		uploadedParts = append(uploadedParts, part)

// 	}
// 	wg.Wait()
// 	return uploadedParts
// }

// func UploadSinglePart(wg sync.WaitGroup, usr CreateUploadSessionResponse, accessToken string, sha1_hash string, chunk Chunk, fileSize int, buffer []byte, partchan chan<- Part) {
// 	body := bytes.NewBuffer(buffer)

// 	client := &http.Client{}
// 	r, _ := http.NewRequest(http.MethodPut, usr.SessionEndpoints.UploadPart, body)

// 	var token = "Bearer " + accessToken
// 	fmt.Println("Found token: ", token)

// 	digestHeader := fmt.Sprintf("sha=%s", sha1_hash)
// 	fmt.Print("Found digest header value: ", digestHeader)

// 	rangeHeader := fmt.Sprintf("bytes %d%s%d%s%d", chunk.offset, "-", int(chunk.offset)+chunk.bufsize-1, "/", fileSize)

// 	fmt.Println("Found range header value: ", rangeHeader)

// 	r.Header.Set("Authorization", token)
// 	r.Header.Set("Content-Type", "application/octet-stream")
// 	r.Header.Set("Digest", digestHeader)
// 	r.Header.Set("Content-Range", rangeHeader)

// 	res, _ := client.Do(r)
// 	fmt.Println("Found response status: ", res.Status)
// 	cl := res.ContentLength
// 	rbs := make([]byte, cl)
// 	res.Body.Read(rbs)
// 	fmt.Println("Found response body: ", string(rbs))

// 	var upr UploadedPartResponse
// 	json.Unmarshal(rbs, &upr)
// 	defer wg.Done()

// 	partchan <- upr.Part

// }

// func CommitUploadSession(accessToken string, fileHash string, commitURL string, partsJson string) string {
// 	fmt.Println("")

// 	fmt.Println("Found commit upload payload: ", partsJson)
// 	fmt.Println("Found file hash: ", fileHash)
// 	fmt.Println("Found commit URL: ", commitURL)

// 	partsBytes := []byte(partsJson)
// 	body := bytes.NewBuffer(partsBytes)
// 	client := &http.Client{}
// 	r, _ := http.NewRequest(http.MethodPost, commitURL, body)
// 	var token = "Bearer " + accessToken
// 	r.Header.Set("Authorization", token)
// 	digestHeader := fmt.Sprintf("sha=%s", fileHash)
// 	r.Header.Set("Digest", digestHeader)
// 	r.Header.Set("Content-Type", "application/json")

// 	res, _ := client.Do(r)
// 	fmt.Println(res.Status)
// 	cl := res.ContentLength
// 	rbs := make([]byte, cl)
// 	res.Body.Read(rbs)
// 	fmt.Println(string(rbs))
// 	return string(rbs)
// }

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

type CreateUploadSessionResponse struct {
	TotalParts        int              `json:"total_parts"`
	PartSize          int              `json:"part_size"`
	SessionEndpoints  SessionEndpoints `json:"session_endpoints"`
	SessionExpiresAt  time.Time        `json:"session_expires_at"`
	ID                string           `json:"id"`
	Type              string           `json:"type"`
	NumPartsProcessed int              `json:"num_parts_processed"`
}
type SessionEndpoints struct {
	ListParts  string `json:"list_parts"`
	Commit     string `json:"commit"`
	LogEvent   string `json:"log_event"`
	UploadPart string `json:"upload_part"`
	Status     string `json:"status"`
	Abort      string `json:"abort"`
}

type CreateUploadSessionRequest struct {
	FileName string `json:"file_name"`
	FileSize int    `json:"file_size"`
	FolderId string `json:"folder_id"`
}

type Chunk struct {
	bufsize int
	offset  int64
}

type UploadedPartResponse struct {
	Part Part `json:"part"`
}
type Part struct {
	Offset int    `json:"offset"`
	PartID string `json:"part_id"`
	Sha1   string `json:"sha1"`
	Size   int    `json:"size"`
}
