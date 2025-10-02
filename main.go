package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT)
	r := gin.Default()

	// Health check endpoint for uptime monitoring (no signature validation needed)
	r.GET("/health", func(ctx *gin.Context) {
		// Log the request for debugging
		log.Printf("Health check request from: %s, User-Agent: %s, Path: %s",
			ctx.ClientIP(), ctx.GetHeader("User-Agent"), ctx.Request.URL.Path)

		ctx.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"bot":    "lunchbot",
			"time":   time.Now().Format("2006-01-02 15:04:05"),
		})
	})

	// Apply signature validation only to SeaTalk webhook endpoints
	protected := r.Group("/")
	protected.Use(WithSOPSignatureValidation())

	protected.POST("/callback", func(ctx *gin.Context) {
		var reqSOP SOPEventCallbackReq
		if err := ctx.BindJSON(&reqSOP); err != nil {
			ctx.JSON(http.StatusInternalServerError, "something wrong")
			return
		}
		log.Printf("INFO: received event with event_type %s", reqSOP.EventType)

		switch reqSOP.EventType {
		case "event_verification":
			ctx.JSON(http.StatusOK, SOPEventVerificationResp{SeatalkChallenge: reqSOP.Event.SeatalkChallenge})
		case "interactive_message_button_clicked":
			log.Printf("INFO: Using interactive_message_button_clicked event")
			handleButtonClick(ctx, reqSOP)
			ctx.JSON(http.StatusOK, "Success")
		case "interactive_message_click":
			log.Printf("INFO: Using interactive_message_click event")
			handleButtonClick(ctx, reqSOP)
			ctx.JSON(http.StatusOK, "Success")
		case "message_from_bot_subscriber":
			handleMessageCommand(ctx, reqSOP, true) // true = private message
			ctx.JSON(http.StatusOK, "Success")
		case "new_mentioned_message_received_from_group_chat":
			handleMessageCommand(ctx, reqSOP, false) // false = group message
			ctx.JSON(http.StatusOK, "Success")
			// default:
			// 	log.Printf("ERROR: event %s not handled yet!", reqSOP.EventType)
			// 	ctx.JSON(http.StatusOK, "Success")
		}
	})

	// Catch-all handler to debug what UptimeRobot is requesting
	r.NoRoute(func(ctx *gin.Context) {
		log.Printf("404 Request: %s %s from %s, User-Agent: %s",
			ctx.Request.Method, ctx.Request.URL.Path, ctx.ClientIP(), ctx.GetHeader("User-Agent"))
		ctx.JSON(http.StatusNotFound, gin.H{
			"error":  "Not Found",
			"path":   ctx.Request.URL.Path,
			"method": ctx.Request.Method,
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Railway prefers 8080
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	go func() {
		log.Println("starting web, listening on", srv.Addr)
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalln("failed starting web on", srv.Addr, err)
		}
	}()

	// Start lunch invite scheduler
	go startLunchScheduler()

	<-c
	log.Println("terminate service")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log.Println("shutting down web on", srv.Addr)
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalln("failed shutdown server", err)
	}
	log.Println("web gracefully stopped")
}

func WithSOPSignatureValidation() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		r := ctx.Request
		signature := r.Header.Get("signature")

		if signature == "" {
			ctx.JSON(http.StatusForbidden, nil)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, err.Error())
			return
		}

		hasher := sha256.New()
		signingSecret := "DgIMEFnLE2z70wkLOOF61PZgdlcMbjX-" // Replace this with your Bot Signing Secret
		hasher.Write(append(body, []byte(signingSecret)...))
		targetSignature := hex.EncodeToString(hasher.Sum(nil))

		if signature != targetSignature {
			ctx.JSON(http.StatusForbidden, nil)
			return
		}

		r.Body = io.NopCloser(bytes.NewBuffer(body))
		ctx.Next()
	}
}

type SOPEventCallbackReq struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	TimeStamp uint64 `json:"timestamp"`
	AppID     string `json:"app_id"`
	Event     Event  `json:"event"`
}

type SOPEventVerificationResp struct {
	SeatalkChallenge string `json:"seatalk_challenge"`
}

type Event struct {
	SeatalkChallenge string          `json:"seatalk_challenge"`
	EmployeeCode     string          `json:"employee_code"`
	EmployeeName     string          `json:"employee_name"`
	UserName         string          `json:"user_name"`
	DisplayName      string          `json:"display_name"`
	FullName         string          `json:"full_name"`
	Email            string          `json:"email"`
	GroupID          string          `json:"group_id"`
	Message          Message         `json:"message"`
	InteractiveData  InteractiveData `json:"interactive_data"`
}

type InteractiveData struct {
	ActionID     string `json:"action_id"`
	Value        string `json:"value"`
	ButtonValue  string `json:"button_value"`
	CallbackData string `json:"callback_data"`
	Data         string `json:"data"`
}

type Message struct {
	Tag  string      `json:"tag"`
	Text TextMessage `json:"text"`
}

type TextMessage struct {
	Content   string `json:"content"`
	PlainText string `json:"plain_text"`
}

type AppAccessToken struct {
	AccessToken string `json:"access_token"`
	ExpireTime  uint64 `json:"expire"`
}

type SOPAuthAppResp struct {
	Code           int    `json:"code"`
	AppAccessToken string `json:"app_access_token"`
	Expire         uint64 `json:"expire"`
}

type LunchParticipant struct {
	EmployeeCode string
	DisplayName  string
}

type SOPSendMessageToUser struct {
	EmployeeCode string     `json:"employee_code"`
	Message      SOPMessage `json:"message"`
}

type SOPSendMessageToGroup struct {
	GroupID string     `json:"group_id"`
	Message SOPMessage `json:"message"`
}

type SOPMessage struct {
	Tag                string                 `json:"tag"`
	Text               *SOPTextMsg            `json:"text,omitempty"`
	InteractiveMessage *SOPInteractiveMessage `json:"interactive_message,omitempty"`
}

type SOPInteractiveMessage struct {
	Elements []SOPInteractiveElement `json:"elements"`
}

type SOPInteractiveElement struct {
	ElementType string                     `json:"element_type"`
	Title       *SOPInteractiveTitle       `json:"title,omitempty"`
	Description *SOPInteractiveDescription `json:"description,omitempty"`
	Button      *SOPInteractiveButton      `json:"button,omitempty"`
}

type SOPInteractiveTitle struct {
	Text string `json:"text"`
}

type SOPInteractiveDescription struct {
	Format int    `json:"format"`
	Text   string `json:"text"`
}

type SOPInteractiveButton struct {
	ButtonType   string `json:"button_type"`
	Text         string `json:"text"`
	Value        string `json:"value"`
	CallbackData string `json:"callback_data,omitempty"`
	ActionID     string `json:"action_id,omitempty"`
}

type SOPTextMsg struct {
	Format  int8   `json:"format"`
	Content string `json:"content"`
}

type SendMessageToUserResp struct {
	Code int `json:"code"`
}

type SeaTalkUserInfo struct {
	Code int `json:"code"`
	Data struct {
		EmployeeCode string `json:"employee_code"`
		Name         string `json:"name"`
		DisplayName  string `json:"display_name"`
		Email        string `json:"email"`
	} `json:"data"`
}

var (
	appAccessToken      AppAccessToken
	dailyLunchResponses = make(map[string][]LunchParticipant) // date -> []participants
	lunchMutex          sync.RWMutex

	// Multiple group support
	lunchGroupIDs = []string{
		"ODM2NjA0MzI4OTIy", // Main lunch group
		// "ANOTHER_GROUP_ID",     // Add more groups here
	}
)

func GetAppAccessToken() AppAccessToken {
	timeNow := time.Now().Unix()

	accTokenIsEmpty := appAccessToken == AppAccessToken{}
	accTokenIsExpired := appAccessToken.ExpireTime < uint64(timeNow)

	if accTokenIsEmpty || accTokenIsExpired {
		body := []byte(fmt.Sprintf(`{"app_id": "%s", "app_secret": "%s"}`, "NDU1NDIwODE1NjAy", "JyKVY6vV3jKmxtLYw8vER-U2HeQTebi7"))

		req, err := http.NewRequest("POST", "https://openapi.seatalk.io/auth/app_access_token", bytes.NewBuffer(body))
		if err != nil {
			log.Printf("ERROR: [GetAppAccessToken] failed to create an HTTP request: %v", err)
			return appAccessToken
		}

		req.Header.Add("Content-Type", "application/json")
		client := &http.Client{}

		res, err := client.Do(req)
		if err != nil {
			log.Printf("ERROR: [GetAppAccessToken] failed to make an HTTP call to seatalk openapi.seatalk.io: %v", err)
			return appAccessToken
		}
		defer res.Body.Close()

		if res.StatusCode != 200 {
			log.Printf("ERROR: [GetAppAccessToken] got non 200 HTTP response status code: %v", err)
			return appAccessToken
		}

		resp := &SOPAuthAppResp{}
		if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
			log.Printf("ERROR: [GetAppAccessToken] failed to parse response body: %v", err)
			return appAccessToken
		}

		if resp.Code != 0 {
			log.Printf("ERROR: [GetAppAccessToken] response code is not 0, error code %d, please refer to the error code documentation https://open.seatalk.io/docs/reference_server-api-error-code", resp.Code)
			return appAccessToken
		}

		appAccessToken = AppAccessToken{
			AccessToken: resp.AppAccessToken,
			ExpireTime:  resp.Expire,
		}
	}

	return appAccessToken
}

func SendMessageToUser(ctx context.Context, message, employeeCode string) error {
	bodyJson, _ := json.Marshal(SOPSendMessageToUser{
		EmployeeCode: employeeCode,
		Message: SOPMessage{
			Tag: "text",
			Text: &SOPTextMsg{
				Format:  2, //plain text message
				Content: message,
			},
		},
	})

	req, err := http.NewRequest("POST", "https://openapi.seatalk.io/messaging/v2/single_chat", bytes.NewBuffer(bodyJson))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")

	// Every SOP API need an authorization, to make sure that our Bot is authorized to call that API. We will use the token that we retrieved on the Step 2.
	req.Header.Add("Authorization", "Bearer "+GetAppAccessToken().AccessToken)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	resp := &SendMessageToUserResp{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return err
	}

	if resp.Code != 0 {
		return fmt.Errorf("something wrong, response code: %v", resp.Code)
	}

	return nil
}

func SendMessageToGroup(ctx context.Context, message, groupID string) error {
	bodyJson, _ := json.Marshal(SOPSendMessageToGroup{
		GroupID: groupID,
		Message: SOPMessage{
			Tag: "text",
			Text: &SOPTextMsg{
				Format:  1, // Rich text format (use 2 for plain text)
				Content: message,
			},
		},
	})

	req, err := http.NewRequest("POST", "https://openapi.seatalk.io/messaging/v2/group_chat", bytes.NewBuffer(bodyJson))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+GetAppAccessToken().AccessToken)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	resp := &SendMessageToUserResp{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return err
	}

	if resp.Code != 0 {
		return fmt.Errorf("failed to send group message, response code: %v", resp.Code)
	}

	return nil
}

// Lunch invite scheduler - runs daily at 11:30 AM
func startLunchScheduler() {
	log.Println("INFO: Starting lunch invite scheduler")

	// Set timezone to GMT+8 (Singapore/Asia)
	location, err := time.LoadLocation("Asia/Singapore")
	if err != nil {
		log.Printf("ERROR: Failed to load timezone, using UTC: %v", err)
		location = time.UTC
	}

	for {
		now := time.Now().In(location)

		// Calculate next 11:30 AM in GMT+8
		next1130 := time.Date(now.Year(), now.Month(), now.Day(), 11, 30, 0, 0, location)
		if now.After(next1130) {
			// If it's already past 11:30 today, schedule for tomorrow
			next1130 = next1130.Add(24 * time.Hour)
		}

		duration := next1130.Sub(now)
		log.Printf("INFO: Next lunch invite scheduled for %s GMT+8 (in %v)", next1130.Format("2006-01-02 15:04:05"), duration)

		// Wait until 11:30 AM
		time.Sleep(duration)

		// Send lunch invite
		if err := sendLunchInvite(); err != nil {
			log.Printf("ERROR: Failed to send lunch invite: %v", err)
		}

		// Sleep for a minute to avoid sending multiple invites
		time.Sleep(time.Minute)
	}
}

func sendLunchInvite() error {
	messageID := fmt.Sprintf("lunch_%d", time.Now().Unix())

	// Send to all configured groups
	for _, groupID := range lunchGroupIDs {
		if err := sendLunchInviteToGroup(groupID, messageID); err != nil {
			log.Printf("ERROR: Failed to send lunch invite to group %s: %v", groupID, err)
			continue
		}
		log.Printf("INFO: Lunch invite sent successfully to group %s", groupID)
	}

	return nil
}

func sendLunchInviteToGroup(groupID, messageID string) error {
	return sendInteractiveLunchInvite(groupID, messageID)
}

func sendInteractiveLunchInvite(groupID, messageID string) error {
	bodyJson, _ := json.Marshal(SOPSendMessageToGroup{
		GroupID: groupID,
		Message: SOPMessage{
			Tag: "interactive_message",
			InteractiveMessage: &SOPInteractiveMessage{
				Elements: []SOPInteractiveElement{
					{
						ElementType: "title",
						Title: &SOPInteractiveTitle{
							Text: "🍽️ Lunch Invite!",
						},
					},
					{
						ElementType: "description",
						Description: &SOPInteractiveDescription{
							Format: 1,
							Text:   "Who's interested in lunch today? Click Accept if you're joining!",
						},
					},
					{
						ElementType: "button",
						Button: &SOPInteractiveButton{
							ButtonType:   "callback",
							Text:         "Accept 🍽️",
							Value:        "lunch_accept_" + messageID,
							CallbackData: "lunch_accept_" + messageID,
							ActionID:     "lunch_accept_" + messageID,
						},
					},
				},
			},
		},
	})

	req, err := http.NewRequest("POST", "https://openapi.seatalk.io/messaging/v2/group_chat", bytes.NewBuffer(bodyJson))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+GetAppAccessToken().AccessToken)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	resp := &SendMessageToUserResp{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return err
	}

	if resp.Code != 0 {
		log.Printf("INFO: Interactive message not supported (code %d), this is expected", resp.Code)
		return fmt.Errorf("failed to send lunch invite, response code: %v", resp.Code)
	}

	return nil
}

func handleMessageCommand(ctx *gin.Context, reqSOP SOPEventCallbackReq, isPrivate bool) {
	message := reqSOP.Event.Message.Text.Content
	if message == "" {
		message = reqSOP.Event.Message.Text.PlainText
	}

	// Helper function to send response to appropriate channel
	sendResponse := func(msg string) error {
		if isPrivate {
			return SendMessageToUser(ctx, msg, reqSOP.Event.EmployeeCode)
		} else {
			return SendMessageToGroup(ctx, msg, reqSOP.Event.GroupID)
		}
	}

	if strings.Contains(strings.ToLower(message), "help") {
		helpMsg := `🍽️ **Lunch Bot Commands**

**How to use:**
• Type "help" to show this message
• Type "jio" (private or @mention) to trigger lunch invite
• Click "Accept 🍽️" button on lunch invites to join

**Features:**
• Daily automatic lunch invites at 11:30 AM
• Shows participant names and count
• Prevents duplicate acceptances per day`

		if err := sendResponse(helpMsg); err != nil {
			log.Printf("ERROR: Failed to send help message: %v", err)
		}
	} else if strings.Contains(strings.ToLower(message), "jio") {
		if err := sendLunchInvite(); err != nil {
			log.Printf("ERROR: Failed to send lunch invite: %v", err)
			if err := sendResponse("❌ Failed to send lunch invite to groups"); err != nil {
				log.Printf("ERROR: Failed to send error message: %v", err)
			}
		}
	} else {
		// Default response for other messages
		if err := sendResponse("Hello! Send 'help' to see available commands or 'jio' to trigger a lunch invite!"); err != nil {
			log.Printf("ERROR: Failed to send default response: %v", err)
		}
	}
}

func handleButtonClick(ctx *gin.Context, reqSOP SOPEventCallbackReq) {
	employeeCode := reqSOP.Event.EmployeeCode
	groupID := reqSOP.Event.GroupID

	log.Printf("INFO: Button clicked by employee: %s in group: %s", employeeCode, groupID)

	// Process lunch acceptance using daily tracking
	handleDailyLunchAcceptWithEvent(ctx, reqSOP.Event, groupID)
}

// Cache for employee names to avoid repeated API calls
var employeeNameCache = make(map[string]string)
var nameCacheMutex sync.RWMutex

func getEmployeeDisplayName(event Event) string {
	// Try to get the best available name from webhook first
	if event.FullName != "" {
		return event.FullName
	}
	if event.DisplayName != "" {
		return event.DisplayName
	}
	if event.EmployeeName != "" {
		return event.EmployeeName
	}
	if event.UserName != "" {
		return event.UserName
	}

	// Try to create a nice name from email
	if event.Email != "" {
		return formatEmailAsName(event.Email)
	}

	// If no name in webhook, try to fetch from SeaTalk API (fallback)
	if name := fetchEmployeeName(event.EmployeeCode); name != "" {
		return name
	}

	// Fallback to employee code
	return event.EmployeeCode
}

func formatEmailAsName(email string) string {
	// Extract name part from email (before @)
	// john.smith@company.com -> john.smith
	parts := strings.Split(email, "@")
	if len(parts) == 0 {
		return email
	}

	namePart := parts[0]

	// Convert dots and underscores to spaces and capitalize
	// john.smith -> John Smith
	// john_smith -> John Smith
	namePart = strings.ReplaceAll(namePart, ".", " ")
	namePart = strings.ReplaceAll(namePart, "_", " ")

	// Capitalize each word
	words := strings.Fields(namePart)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
		}
	}

	return strings.Join(words, " ")
}

func fetchEmployeeName(employeeCode string) string {
	// Check cache first
	nameCacheMutex.RLock()
	if cachedName, exists := employeeNameCache[employeeCode]; exists {
		nameCacheMutex.RUnlock()
		return cachedName
	}
	nameCacheMutex.RUnlock()

	// Try to fetch from SeaTalk User API
	url := fmt.Sprintf("https://openapi.seatalk.io/user/v1/info?employee_code=%s", employeeCode)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("ERROR: Failed to create user info request: %v", err)
		return ""
	}

	token := GetAppAccessToken().AccessToken
	req.Header.Add("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 5 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		log.Printf("ERROR: Failed to fetch user info: %v", err)
		return ""
	}
	defer res.Body.Close()

	var userInfo SeaTalkUserInfo
	if err := json.NewDecoder(res.Body).Decode(&userInfo); err != nil {
		log.Printf("ERROR: Failed to decode user info: %v", err)
		return ""
	}

	if userInfo.Code != 0 {
		log.Printf("WARNING: SeaTalk user info API returned code %d for employee %s", userInfo.Code, employeeCode)
		return ""
	}

	// Use display name if available, otherwise use name
	displayName := userInfo.Data.DisplayName
	if displayName == "" {
		displayName = userInfo.Data.Name
	}

	if displayName != "" {
		// Cache the result
		nameCacheMutex.Lock()
		employeeNameCache[employeeCode] = displayName
		nameCacheMutex.Unlock()

		log.Printf("INFO: Fetched name for employee %s: %s", employeeCode, displayName)
		return displayName
	}

	return ""
}

func handleDailyLunchAcceptWithEvent(ctx *gin.Context, event Event, groupID string) {
	lunchMutex.Lock()
	defer lunchMutex.Unlock()

	employeeCode := event.EmployeeCode
	displayName := getEmployeeDisplayName(event)

	// Use today's date as the key for daily tracking
	today := time.Now().Format("2006-01-02")

	// Initialize today's responses if it doesn't exist
	if _, exists := dailyLunchResponses[today]; !exists {
		dailyLunchResponses[today] = []LunchParticipant{}
	}

	// Check if this employee already accepted today
	for _, participant := range dailyLunchResponses[today] {
		if participant.EmployeeCode == employeeCode {
			log.Printf("INFO: Employee %s (%s) already accepted lunch today (%s) - ignoring duplicate click", employeeCode, displayName, today)
			// Silently ignore duplicate clicks - no message sent
			return
		}
	}

	// Add employee to today's responses
	newParticipant := LunchParticipant{
		EmployeeCode: employeeCode,
		DisplayName:  displayName,
	}
	dailyLunchResponses[today] = append(dailyLunchResponses[today], newParticipant)
	newCount := len(dailyLunchResponses[today])

	log.Printf("INFO: Employee %s (%s) accepted today's lunch (%s). Total acceptances: %d", employeeCode, displayName, today, newCount)

	// Send enhanced confirmation message
	confirmMsg := fmt.Sprintf(`🎉 **%s just accepted today's lunch!**

📊 **Today's Status (%s):**
👥 Total people: **%d**
✅ Accepted by:
%s

%s`,
		displayName,
		today,
		newCount,
		formatParticipantNames(dailyLunchResponses[today]),
		getLunchStatusEmoji(newCount))

	if err := SendMessageToGroup(ctx, confirmMsg, groupID); err != nil {
		log.Printf("ERROR: Failed to send lunch confirmation: %v", err)
	}
}

func formatParticipantNames(participants []LunchParticipant) string {
	if len(participants) == 0 {
		return "_No one yet_"
	}

	// Create bullet list format
	var nameList []string
	for _, participant := range participants {
		nameList = append(nameList, "• "+participant.DisplayName)
	}

	return strings.Join(nameList, "\n")
}

func getLunchStatusEmoji(count int) string {
	switch {
	case count == 1:
		return "🍽️ _Am I going to eat alone today? T.T_"
	case count >= 2 && count <= 4:
		return "🍽️ _Nice lah, got more people join me le! Let's decide a place to eat!_"
	case count >= 5 && count <= 8:
		return "🍽️ Shiok! This is going to be a fun lunch! Confirm got place le hor?_"
	case count > 8:
		return "🍽️ _Waseh! This is going to be a big lunch party! Let's eat something scrumptious!_"
	default:
		return "🍽️ _Let's eat!_"
	}
}
