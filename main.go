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
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

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
	Value            string          `json:"value"`
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

var (
	appAccessToken      AppAccessToken
	dailyLunchResponses = make(map[string][]LunchParticipant) // date -> []accepted participants
	dailyLunchDeclined  = make(map[string][]LunchParticipant) // date -> []declined participants
	lunchMutex          sync.RWMutex

	// Multiple group support
	lunchGroupIDs = []string{
		"ODM2NjA0MzI4OTIy", // Main lunch group ODM2NjA0MzI4OTIy
		// "ANOTHER_GROUP_ID",     // Add more groups here
	}

	// BFT reminder group (you can set this to same group or different group)
	bftGroupID = "MDkwNjg0MDMzMzAw" // BFT reminder group - change this if needed

	// BFT response tracking - daily tracking instead of per-message
	dailyBFTResponses = make(map[string]map[string][]string) // date -> employeeCode -> [button_types_pressed]
	bftMutex          sync.RWMutex

	// Lunch response tracking for interactive buttons - daily tracking instead of per-message
	dailyLunchButtonResponses = make(map[string]map[string][]string) // date -> employeeCode -> [button_types_pressed]
	lunchButtonMutex          sync.RWMutex
)

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT)
	r := gin.Default()

	// Health check endpoint for uptime monitoring (no signature validation needed)
	healthHandler := func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"bot":    "lunchbot",
			"time":   time.Now().Format("2006-01-02 15:04:05"),
		})
	}

	// Support both GET and HEAD requests for health checks
	r.GET("/health", healthHandler)
	r.HEAD("/health", healthHandler)

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
		case "interactive_message_click":
			handleButtonClick(ctx, reqSOP)
			ctx.JSON(http.StatusOK, "Success")
		case "message_from_bot_subscriber":
			handleMessageCommand(ctx, reqSOP, true) // true = private message
			ctx.JSON(http.StatusOK, "Success")
		case "new_mentioned_message_received_from_group_chat":
			handleMessageCommand(ctx, reqSOP, false) // false = group message
			ctx.JSON(http.StatusOK, "Success")
		default:
			log.Printf("event %s not handled yet!", reqSOP.EventType)
			ctx.JSON(http.StatusOK, "Success")
		}
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

	// Start BFT reminder scheduler
	go startBFTScheduler()

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
• Type 'help' to trigger this message
• Type 'jio' to trigger lunch invite
• Type 'status' to see today's lunch invite status
• Type 'bft' to trigger BFT reminder

**Features:**
• Daily automatic lunch invites at 11:30 AM (weekdays only)
• Daily automatic BFT reminders at 12:00 PM (weekdays only)`

		if err := sendResponse(helpMsg); err != nil {
			log.Printf("ERROR: Failed to send help message: %v", err)
		}
	} else if strings.Contains(strings.ToLower(message), "status") {
		statusMsg := getTodayLunchStatus()
		if err := sendResponse(statusMsg); err != nil {
			log.Printf("ERROR: Failed to send status message: %v", err)
		}
	} else if strings.Contains(strings.ToLower(message), "bft") {
		if err := sendBFTReminder(); err != nil {
			log.Printf("ERROR: Failed to send BFT reminder: %v", err)
			if err := sendResponse("❌ Failed to send BFT reminder to group"); err != nil {
				log.Printf("ERROR: Failed to send error message: %v", err)
			}
		} else {
			// Send confirmation only for private messages
			if isPrivate {
				if err := sendResponse("💪 BFT reminder sent successfully to group!"); err != nil {
					log.Printf("ERROR: Failed to send confirmation message: %v", err)
				}
			}
		}
	} else if strings.Contains(strings.ToLower(message), "jio") {
		if err := sendLunchInvite(); err != nil {
			log.Printf("ERROR: Failed to send lunch invite: %v", err)
			if err := sendResponse("❌ Failed to send lunch invite to groups"); err != nil {
				log.Printf("ERROR: Failed to send error message: %v", err)
			}
		} else {
			// Send confirmation only for private messages
			if isPrivate {
				if err := sendResponse("✅ Lunch invite sent successfully to 1 group(s)!"); err != nil {
					log.Printf("ERROR: Failed to send confirmation message: %v", err)
				}
			}
		}
	} else {
		// Default response for other messages
		if err := sendResponse("Hello! Type 'help' to see available commands!"); err != nil {
			log.Printf("ERROR: Failed to send default response: %v", err)
		}
	}
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

		// Skip weekends - find next weekday
		for next1130.Weekday() == time.Saturday || next1130.Weekday() == time.Sunday {
			next1130 = next1130.Add(24 * time.Hour)
		}

		duration := next1130.Sub(now)
		log.Printf("INFO: Next lunch invite scheduled for %s GMT+8 (in %v)", next1130.Format("2006-01-02 15:04:05"), duration)

		// Wait until 11:30 AM on a weekday
		time.Sleep(duration)

		// Double-check it's a weekday before sending (safety check)
		currentTime := time.Now().In(location)
		if currentTime.Weekday() != time.Saturday && currentTime.Weekday() != time.Sunday {
			// Send lunch invite
			if err := sendLunchInvite(); err != nil {
				log.Printf("ERROR: Failed to send lunch invite: %v", err)
			}
		}

		// Sleep for a minute to avoid sending multiple invites
		time.Sleep(time.Minute)
	}
}

func sendLunchInvite() error {
	today := time.Now().In(getTimezone()).Format("2006-01-02")
	messageID := fmt.Sprintf("lunch_%d", time.Now().Unix())
	todayFormatted := time.Now().In(getTimezone()).Format("Monday, 2 January 2006")

	// Send to all configured groups
	for _, groupID := range lunchGroupIDs {
		bodyJson, _ := json.Marshal(SOPSendMessageToGroup{
			GroupID: groupID,
			Message: SOPMessage{
				Tag: "interactive_message",
				InteractiveMessage: &SOPInteractiveMessage{
					Elements: []SOPInteractiveElement{
						{
							ElementType: "title",
							Title: &SOPInteractiveTitle{
								Text: fmt.Sprintf("🍽️ Lunch Invite for %s!", todayFormatted),
							},
						},
						{
							ElementType: "description",
							Description: &SOPInteractiveDescription{
								Format: 1,
								Text:   "Who's interested in lunch today at 12:15pm?",
							},
						},
						{
							ElementType: "button",
							Button: &SOPInteractiveButton{
								ButtonType:   "callback",
								Text:         "I'm joining! 🍽️",
								Value:        "lunch_join_" + messageID,
								CallbackData: "lunch_join_" + messageID,
								ActionID:     "lunch_join_" + messageID,
							},
						},
						{
							ElementType: "button",
							Button: &SOPInteractiveButton{
								ButtonType:   "callback",
								Text:         "I'm skipping 😴",
								Value:        "lunch_skip_" + messageID,
								CallbackData: "lunch_skip_" + messageID,
								ActionID:     "lunch_skip_" + messageID,
							},
						},
					},
				},
			},
		})

		req, err := http.NewRequest("POST", "https://openapi.seatalk.io/messaging/v2/group_chat", bytes.NewBuffer(bodyJson))
		if err != nil {
			log.Printf("ERROR: Failed to send lunch invite to group %s: %v", groupID, err)
			continue
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", "Bearer "+GetAppAccessToken().AccessToken)

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			log.Printf("ERROR: Failed to send lunch invite to group %s: %v", groupID, err)
			continue
		}
		defer res.Body.Close()

		resp := &SendMessageToUserResp{}
		if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
			log.Printf("ERROR: Failed to send lunch invite to group %s: %v", groupID, err)
			continue
		}

		if resp.Code != 0 {
			log.Printf("ERROR: Failed to send lunch invite to group %s, response code: %v", groupID, resp.Code)
			continue
		}

		log.Printf("INFO: Lunch invite sent successfully to group %s", groupID)
	}

	log.Printf("INFO: Lunch invite sent to %d group(s) for %s", len(lunchGroupIDs), today)
	return nil
}

// BFT reminder scheduler - runs daily at 12:00 PM on weekdays
func startBFTScheduler() {
	log.Println("INFO: Starting BFT reminder scheduler")

	// Set timezone to GMT+8 (Singapore/Asia)
	location, err := time.LoadLocation("Asia/Singapore")
	if err != nil {
		log.Printf("ERROR: Failed to load timezone, using UTC: %v", err)
		location = time.UTC
	}

	for {
		now := time.Now().In(location)

		// Calculate next 12:00 PM in GMT+8
		next1200 := time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, location)
		if now.After(next1200) {
			// If it's already past 12:00 today, schedule for tomorrow
			next1200 = next1200.Add(24 * time.Hour)
		}

		// Skip weekends - find next weekday
		for next1200.Weekday() == time.Saturday || next1200.Weekday() == time.Sunday {
			next1200 = next1200.Add(24 * time.Hour)
		}

		duration := next1200.Sub(now)
		log.Printf("INFO: Next BFT reminder scheduled for %s GMT+8 (in %v)", next1200.Format("2006-01-02 15:04:05"), duration)

		// Wait until 12:00 PM on a weekday
		time.Sleep(duration)

		// Double-check it's a weekday before sending (safety check)
		currentTime := time.Now().In(location)
		if currentTime.Weekday() != time.Saturday && currentTime.Weekday() != time.Sunday {
			// Send BFT reminder (scheduler sends once, but manual "bft" commands can send more)
			if err := sendBFTReminder(); err != nil {
				log.Printf("ERROR: Failed to send BFT reminder: %v", err)
			}
		}

		// Sleep for a minute to avoid sending multiple reminders
		time.Sleep(time.Minute)
	}
}

func sendBFTReminder() error {
	today := time.Now().In(getTimezone()).Format("Monday, 2 January 2006")
	messageID := fmt.Sprintf("%d", time.Now().Unix())

	bodyJson, _ := json.Marshal(SOPSendMessageToGroup{
		GroupID: bftGroupID,
		Message: SOPMessage{
			Tag: "interactive_message",
			InteractiveMessage: &SOPInteractiveMessage{
				Elements: []SOPInteractiveElement{
					{
						ElementType: "title",
						Title: &SOPInteractiveTitle{
							Text: fmt.Sprintf("💪 BFT Session Reminder - %s", today),
						},
					},
					{
						ElementType: "description",
						Description: &SOPInteractiveDescription{
							Format: 1,
							Text: `🏃‍♂️ **Body Fit Training session is coming up at 12:15pm!**

📋 **Please prepare:**
• Wear appropriate workout clothes
• Bring water bottle
• Bring bft³
• Bring shower stuff and change of clothes
• Be ready to move and sweat! 💦

⏰ **Time to get fit and healthy!**

Let us know if you're joining today! 🔥`,
						},
					},
					{
						ElementType: "button",
						Button: &SOPInteractiveButton{
							ButtonType:   "callback",
							Text:         "I'm going! 💪",
							Value:        "bft_going_" + messageID,
							CallbackData: "bft_going_" + messageID,
							ActionID:     "bft_going_" + messageID,
						},
					},
					{
						ElementType: "button",
						Button: &SOPInteractiveButton{
							ButtonType:   "callback",
							Text:         "I'm skipping today 😴",
							Value:        "bft_skip_" + messageID,
							CallbackData: "bft_skip_" + messageID,
							ActionID:     "bft_skip_" + messageID,
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
		return fmt.Errorf("failed to send BFT interactive reminder, response code: %v", resp.Code)
	}

	log.Printf("INFO: BFT interactive reminder sent successfully to group %s", bftGroupID)
	return nil
}

func handleButtonClick(ctx *gin.Context, reqSOP SOPEventCallbackReq) {
	buttonValue := reqSOP.Event.Value

	// Check if this is a BFT button
	if strings.Contains(buttonValue, "bft_going_") || strings.Contains(buttonValue, "bft_skip_") {
		handleBFTButtonClick(ctx, reqSOP)
		return
	}

	// Check if this is a lunch interactive button
	if strings.Contains(buttonValue, "lunch_join_") || strings.Contains(buttonValue, "lunch_skip_") {
		handleLunchButtonClick(ctx, reqSOP)
		return
	}
}

func handleLunchButtonClick(ctx *gin.Context, reqSOP SOPEventCallbackReq) {
	employeeCode := reqSOP.Event.EmployeeCode
	buttonValue := reqSOP.Event.Value
	groupID := reqSOP.Event.GroupID
	displayName := getEmployeeDisplayName(reqSOP.Event)
	today := time.Now().Format("2006-01-02")

	// Extract button type from the button value
	var buttonType string
	if strings.Contains(buttonValue, "lunch_join_") {
		buttonType = "join"
	} else if strings.Contains(buttonValue, "lunch_skip_") {
		buttonType = "skip"
	} else {
		log.Printf("WARNING: Unknown lunch button value: '%s'", buttonValue)
		return
	}

	// Check user's previous responses for today (across all lunch invites)
	lunchButtonMutex.Lock()
	if dailyLunchButtonResponses[today] == nil {
		dailyLunchButtonResponses[today] = make(map[string][]string)
	}

	userResponses := dailyLunchButtonResponses[today][employeeCode]

	// Check if user has already pressed both buttons today
	hasJoin := containsString(userResponses, "join")
	hasSkip := containsString(userResponses, "skip")

	if hasJoin && hasSkip {
		lunchButtonMutex.Unlock()
		log.Printf("INFO: User %s (%s) has already used both lunch buttons today (%s), blocking further clicks", displayName, employeeCode, today)
		return
	}

	// Check if user is clicking the same button again today
	if containsString(userResponses, buttonType) {
		lunchButtonMutex.Unlock()
		log.Printf("INFO: User %s (%s) already clicked %s button for lunch today (%s), ignoring duplicate", displayName, employeeCode, buttonType, today)
		return
	}

	// Add this button type to user's daily response history
	dailyLunchButtonResponses[today][employeeCode] = append(userResponses, buttonType)
	isSecondButton := len(userResponses) > 0 // This will be the second button press today
	lunchButtonMutex.Unlock()

	// Process the button click using existing lunch logic
	switch buttonType {
	case "join":
		handleLunchJoin(ctx, reqSOP.Event, groupID, isSecondButton)
	case "skip":
		handleLunchSkip(ctx, reqSOP.Event, groupID, isSecondButton)
	}
}

func handleBFTButtonClick(ctx *gin.Context, reqSOP SOPEventCallbackReq) {
	employeeCode := reqSOP.Event.EmployeeCode
	buttonValue := reqSOP.Event.Value
	groupID := reqSOP.Event.GroupID
	displayName := getEmployeeDisplayName(reqSOP.Event)
	today := time.Now().Format("2006-01-02")

	// Extract button type from the button value
	var buttonType string
	if strings.Contains(buttonValue, "bft_going_") {
		buttonType = "going"
	} else if strings.Contains(buttonValue, "bft_skip_") {
		buttonType = "skip"
	} else {
		log.Printf("WARNING: Unknown BFT button value: '%s'", buttonValue)
		return
	}

	// Check user's previous responses for today (across all BFT reminders)
	bftMutex.Lock()
	if dailyBFTResponses[today] == nil {
		dailyBFTResponses[today] = make(map[string][]string)
	}

	userResponses := dailyBFTResponses[today][employeeCode]

	// Check if user has already pressed both buttons today
	hasGoing := containsString(userResponses, "going")
	hasSkip := containsString(userResponses, "skip")

	if hasGoing && hasSkip {
		bftMutex.Unlock()
		log.Printf("INFO: User %s (%s) has already used both BFT buttons today (%s), blocking further clicks", displayName, employeeCode, today)
		return
	}

	// Check if user is clicking the same button again today
	if containsString(userResponses, buttonType) {
		bftMutex.Unlock()
		log.Printf("INFO: User %s (%s) already clicked %s button for BFT today (%s), ignoring duplicate", displayName, employeeCode, buttonType, today)
		return
	}

	// Add this button type to user's daily response history
	dailyBFTResponses[today][employeeCode] = append(userResponses, buttonType)
	isSecondButton := len(userResponses) > 0 // This will be the second button press today
	bftMutex.Unlock()

	// Process the button click
	switch buttonType {
	case "going":
		handleBFTGoing(ctx, reqSOP.Event, groupID, isSecondButton)
	case "skip":
		handleBFTSkip(ctx, reqSOP.Event, groupID, isSecondButton)
	}
}

func handleLunchJoin(ctx *gin.Context, event Event, groupID string, isSecondButton bool) {
	// Use the existing lunch accept logic
	lunchMutex.Lock()
	defer lunchMutex.Unlock()

	employeeCode := event.EmployeeCode
	displayName := getEmployeeDisplayName(event)
	today := time.Now().Format("2006-01-02")

	// Initialize today's responses if they don't exist
	if _, exists := dailyLunchResponses[today]; !exists {
		dailyLunchResponses[today] = []LunchParticipant{}
	}
	if _, exists := dailyLunchDeclined[today]; !exists {
		dailyLunchDeclined[today] = []LunchParticipant{}
	}

	// Check if this employee already accepted today
	for _, participant := range dailyLunchResponses[today] {
		if participant.EmployeeCode == employeeCode {
			return
		}
	}

	// Remove employee from declined list if they were previously declined
	var updatedDeclined []LunchParticipant
	for _, participant := range dailyLunchDeclined[today] {
		if participant.EmployeeCode != employeeCode {
			updatedDeclined = append(updatedDeclined, participant)
		}
	}
	dailyLunchDeclined[today] = updatedDeclined

	// Add employee to today's accepted responses
	newParticipant := LunchParticipant{
		EmployeeCode: employeeCode,
		DisplayName:  displayName,
	}
	dailyLunchResponses[today] = append(dailyLunchResponses[today], newParticipant)

	// Send confirmation message with randomized cheer
	cheerMessage := getRandomCheerMessage("lunch", "accept", displayName, isSecondButton)
	confirmMsg := formatLunchStatusWithData([]string{cheerMessage}, today, dailyLunchResponses[today], dailyLunchDeclined[today])

	if err := SendMessageToGroup(ctx, confirmMsg, groupID); err != nil {
		log.Printf("ERROR: Failed to send lunch join confirmation: %v", err)
	} else {
		log.Printf("INFO: %s (%s) joined lunch for %s. Total accepted: %d", displayName, employeeCode, today, len(dailyLunchResponses[today]))
	}
}

func handleLunchSkip(ctx *gin.Context, event Event, groupID string, isSecondButton bool) {
	lunchMutex.Lock()
	defer lunchMutex.Unlock()

	employeeCode := event.EmployeeCode
	displayName := getEmployeeDisplayName(event)
	today := time.Now().Format("2006-01-02")

	// Initialize today's responses if they don't exist
	if _, exists := dailyLunchResponses[today]; !exists {
		dailyLunchResponses[today] = []LunchParticipant{}
	}
	if _, exists := dailyLunchDeclined[today]; !exists {
		dailyLunchDeclined[today] = []LunchParticipant{}
	}

	// Remove employee from accepted list if they were previously joined
	var updatedAccepted []LunchParticipant
	for _, participant := range dailyLunchResponses[today] {
		if participant.EmployeeCode != employeeCode {
			updatedAccepted = append(updatedAccepted, participant)
		}
	}
	dailyLunchResponses[today] = updatedAccepted

	// Add employee to declined list if not already there
	alreadyDeclined := false
	for _, participant := range dailyLunchDeclined[today] {
		if participant.EmployeeCode == employeeCode {
			alreadyDeclined = true
			break
		}
	}

	if !alreadyDeclined {
		newDeclined := LunchParticipant{
			EmployeeCode: employeeCode,
			DisplayName:  displayName,
		}
		dailyLunchDeclined[today] = append(dailyLunchDeclined[today], newDeclined)
	}

	// Send skip message with current status
	cheerMessage := getRandomCheerMessage("lunch", "decline", displayName, isSecondButton)
	skipMsg := formatLunchStatusWithData([]string{cheerMessage}, today, dailyLunchResponses[today], dailyLunchDeclined[today])

	if err := SendMessageToGroup(ctx, skipMsg, groupID); err != nil {
		log.Printf("ERROR: Failed to send lunch skip confirmation: %v", err)
	} else {
		log.Printf("INFO: %s (%s) declined lunch for %s. Total accepted: %d, Total declined: %d", displayName, employeeCode, today, len(dailyLunchResponses[today]), len(dailyLunchDeclined[today]))
	}
}

func handleBFTGoing(ctx *gin.Context, event Event, groupID string, isSecondButton bool) {
	displayName := getEmployeeDisplayName(event)
	today := time.Now().Format("2006-01-02")

	message := getRandomCheerMessage("bft", "going", displayName, isSecondButton)

	if err := SendMessageToGroup(ctx, message, groupID); err != nil {
		log.Printf("ERROR: Failed to send BFT going confirmation: %v", err)
	} else {
		log.Printf("INFO: %s (%s) going to BFT for %s", displayName, event.EmployeeCode, today)
	}
}

func handleBFTSkip(ctx *gin.Context, event Event, groupID string, isSecondButton bool) {
	displayName := getEmployeeDisplayName(event)
	today := time.Now().Format("2006-01-02")

	message := getRandomCheerMessage("bft", "skip", displayName, isSecondButton)

	if err := SendMessageToGroup(ctx, message, groupID); err != nil {
		log.Printf("ERROR: Failed to send BFT skip confirmation: %v", err)
	} else {
		log.Printf("INFO: %s (%s) skipping BFT for %s", displayName, event.EmployeeCode, today)
	}
}

// Helper function to check if slice contains a string
func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getEmployeeDisplayName(event Event) string {
	// Create name from email
	if event.Email != "" {
		return formatEmailAsName(event.Email)
	}

	// Fallback to employee code if no email
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

func getTimezone() *time.Location {
	location, err := time.LoadLocation("Asia/Singapore")
	if err != nil {
		return time.UTC
	}
	return location
}

func getTodayLunchStatus(cheerMessage ...string) string {
	lunchMutex.RLock()
	defer lunchMutex.RUnlock()

	today := time.Now().In(getTimezone()).Format("2006-01-02")
	accepted, existsAccepted := dailyLunchResponses[today]
	declined, existsDeclined := dailyLunchDeclined[today]

	if !existsAccepted {
		accepted = []LunchParticipant{}
	}
	if !existsDeclined {
		declined = []LunchParticipant{}
	}

	return formatLunchStatusWithData(cheerMessage, today, accepted, declined)
}

func formatLunchStatusWithData(cheerMessage []string, today string, accepted []LunchParticipant, declined ...[]LunchParticipant) string {
	acceptedCount := len(accepted)
	var declinedList []LunchParticipant
	if len(declined) > 0 {
		declinedList = declined[0]
	}

	// Build the status message parts
	var parts []string

	// Add cheer message if provided
	if len(cheerMessage) > 0 && cheerMessage[0] != "" {
		parts = append(parts, cheerMessage[0])
	}

	// Add status section
	if acceptedCount == 0 && len(declinedList) == 0 {
		statusSection := fmt.Sprintf(`📊 **Today's Status (%s):**
👥 Total people accepted: **0**
❌ No one has responded to lunch yet today`, today)
		parts = append(parts, statusSection)
	} else {
		statusSection := fmt.Sprintf(`📊 **Today's Status (%s):**
👥 Total people accepted: **%d**`, today, acceptedCount)

		if acceptedCount > 0 {
			statusSection += fmt.Sprintf(`
✅ Accepted by:
%s`, formatParticipantNames(accepted))
		} else {
			statusSection += `
❌ No one has accepted lunch yet today`
		}

		// Always show declined list if there are declined participants
		if len(declinedList) > 0 {
			statusSection += fmt.Sprintf(`

❌ Declined by:
%s`, formatParticipantNames(declinedList))
		}

		parts = append(parts, statusSection)
	}

	// Add emoji message if cheer message was provided (indicating this is from button response)
	if len(cheerMessage) > 0 && cheerMessage[0] != "" {
		parts = append(parts, getLunchStatusEmoji(acceptedCount))
	}

	return strings.Join(parts, "\n\n")
}

func getLunchStatusEmoji(count int) string {
	switch {
	case count == 1:
		return "😢 _Sadge, am I going to eat alone today? T.T_"
	case count == 2:
		return "👥 Swee la, got more people join me le! Is it going to be just 2 of us?_ 🤔"
	case count == 3:
		return "👫👤 _3 people nia, anyone else wanna make another pair?_ 🙋‍♂️"
	case count == 4:
		return "👨‍👩‍👧‍👦 _It will be a shiok lunch with 4 pax! Confirm got place to eat le mah?_ 🎉"
	case count > 4:
		return "🎊 _Waseh! This is going to be a big lunch party! Let's eat something scrumptious!_ 🥳🍜"
	default:
		return "🍽️💨 _Today's lunch bo lang kang kang!_ 😅🤷‍♂️"
	}
}

// getRandomCheerMessage generates randomized responses for different event types
func getRandomCheerMessage(eventType, action, displayName string, isSecondButton bool) string {
	// Add action-specific prefix
	actionLabel := "[Accepted] "
	if action == "decline" || action == "skip" {
		actionLabel = "[Declined] "
	}

	titlePrefix := actionLabel
	if isSecondButton {
		titlePrefix = "<Prata-ed> " + actionLabel
	}

	var responses []string

	switch eventType {
	case "lunch":
		switch action {
		case "accept":
			responses = []string{
				"🍽️ **%s%s ready to makan liao!** Let's go chope table! 🎉",
				"🥘 **%s%s join the makan gang!** Time to find good food! 😋",
				"🍜 **%s%s stomach growling already!** Lunch gonna be shiok! 🔥",
				"🥗 **%s%s confirm hungry lah!** Let's make this meal memorable! 💯",
				"🍛 **%s%s ready for food adventure!** Jom makan! 🚀",
				"🍲 **%s%s showing up with empty stomach!** This lunch gonna be power! ⭐",
				"🥙 **%s%s locked and loaded for makan!** Time to satisfy those cravings! 🎯",
				"🍱 **%s%s battery low, need food!** Let's discover something sedap! ✨",
			}
		case "decline":
			responses = []string{
				"😔 **%s%s cannot make it today.** Next time jio you again! 🍽️",
				"🏠 **%s%s staying in office today.** We miss you at lunch leh! 💤",
				"📚 **%s%s got other commitments.** Catch you for next makan session! 👋",
				"☕ **%s%s going solo today.** Also can lah! ☕",
				"💼 **%s%s too busy with work.** Don't forget to eat ah! 🛋️",
				"🥪 **%s%s got other food plans.** Hope it's sedap! 😊",
				"📱 **%s%s got different arrangement.** See you next time! 🤗",
				"🍕 **%s%s going for something else.** Enjoy your makan! 😄",
			}
		}
	case "bft":
		switch action {
		case "going":
			responses = []string{
				"💪 **%s%s confirm going lah!** Ready to sweat like siao! 🔥",
				"🏃‍♂️ **%s%s join the gang already!** Time to chiong ah! 💦",
				"⚡ **%s%s sibei on today!** BFT here we come liao! 🚀",
				"🔥 **%s%s damn committed sia!** Fitness mode activated! 💯",
				"💥 **%s%s ready to hoot!** Let's make those muscles cry! 🏋️‍♂️",
				"🌟 **%s%s showing face strong strong!** BFT session gonna be shiok! ⭐",
				"🎯 **%s%s locked and loaded liao!** Time to push until pengsan! 🚀",
				"🔋 **%s%s battery full full!** Let's burn those calories like mad! 🔥",
			}
		case "skip":
			responses = []string{
				"😴 **%s%s taking MC today lah.** Sometimes rest is best mah! 🛌",
				"🏠 **%s%s sitting out this round.** We miss you at BFT leh! 💤",
				"📚 **%s%s got other things to do.** Next time jio you again! 👋",
				"☕ **%s%s choose kopi over cardio.** Also can lah! ☕",
				"🎮 **%s%s want to slack today.** Self-care also important what! 🛋️",
				"🌙 **%s%s need to recharge battery.** Rest well for next session! 😊",
				"📱 **%s%s got other plans liao.** Hope to see you next time! 🤗",
				"🍕 **%s%s choose shiok over sweat.** We understand one! 😄",
			}
		}
	}

	// Fallback if no responses found
	if len(responses) == 0 {
		return fmt.Sprintf("**%s%s updated their response!**", titlePrefix, displayName)
	}

	// Seed random number generator and select response
	rand.Seed(time.Now().UnixNano())
	selectedResponse := responses[rand.Intn(len(responses))]
	return fmt.Sprintf(selectedResponse, titlePrefix, displayName)
}
