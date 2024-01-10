package thirdpartyoauth

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// WxOfficialHandler 微信公众号
type WxOfficialHandler struct {
	BaseOauthConfig

	AccessToken string
	JsapiTicket string

	accessTokenExpireAt time.Time
	jsapiTicketExipreAt time.Time
}

type WxOfficialAccessToken struct {
	CommonErrResp
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type WxOfficialJsApiTicket struct {
	CommonErrResp
	Ticket    string `json:"ticket"`
	ExpiresIn int    `json:"expires_in"`
}

type WxOfficialJsApiConfig struct {
	AppId     string `json:"appId"`
	Timestamp string `json:"timestamp"`
	NonceStr  string `json:"nonceStr"`
	Signature string `json:"signature"`
}

// NewWxOfficialHandler 微信公众号授权工具
func NewWxOfficialHandler(appId, appSecret string) *WxOfficialHandler {
	return &WxOfficialHandler{
		BaseOauthConfig: BaseOauthConfig{
			appId:     appId,
			appSecret: appSecret,
		},
	}
}

// GetAccessToken 获取公众号的accessToken
func (w *WxOfficialHandler) GetAccessToken(ctx context.Context) (*WxOfficialAccessToken, error) {
	url := w.buildAccessTokenUrl()
	result := &WxOfficialAccessToken{}
	err := httpGet(ctx, url, &result)
	if err != nil {
		return nil, err
	}

	if result.Errcode != 0 {
		return nil, fmt.Errorf("errCode: %d errMsg: %s", result.Errcode, result.Errmsg)
	}

	w.AccessToken = result.AccessToken
	w.accessTokenExpireAt = time.Now().Add(time.Second*time.Duration(result.ExpiresIn) - time.Hour) // 默认减去1小时

	return result, nil
}

func (w *WxOfficialHandler) buildAccessTokenUrl() string {
	url := NewUrlHelper(wxCgiBinAccessTokenUrl).
		AddParam("grant_type", grantTypeClientCredential).
		AddParam("appid", w.appId).
		AddParam("secret", w.appSecret).
		Build()
	return url
}

// GetJsApiTicket 获取js-sdk的ticket
func (w *WxOfficialHandler) GetJsApiTicket(ctx context.Context, accessToken string) (*WxOfficialJsApiTicket, error) {
	url := w.buildJsApiTicketUrl(accessToken)
	result := &WxOfficialJsApiTicket{}
	err := httpGet(ctx, url, &result)
	if err != nil {
		return nil, err
	}

	if result.Errcode != 0 {
		return nil, fmt.Errorf("errCode: %d errMsg: %s", result.Errcode, result.Errmsg)
	}

	w.JsapiTicket = result.Ticket
	w.jsapiTicketExipreAt = time.Now().Add(time.Second*time.Duration(result.ExpiresIn) - time.Hour) // 默认减去1小时

	return result, nil
}

func (w *WxOfficialHandler) buildJsApiTicketUrl(accessToken string) string {
	url := NewUrlHelper(wxCgiBinJsApiTicketUrl).
		AddParam("access_token", accessToken).
		AddParam("type", "jsapi").
		Build()
	return url
}

// GetJsApiConfig 获取js-sdk的config
func (w *WxOfficialHandler) GetJsApiConfig(ctx context.Context, ticket, url string) *WxOfficialJsApiConfig {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10) // int64 ==> string
	nonceStr := GetNonceStr(NonceStrLength)
	signatureStr := "jsapi_ticket=" + ticket + "&noncestr=" + nonceStr + "&timestamp=" + timestamp + "&url=" + url
	signature := GetSha1(signatureStr)
	return &WxOfficialJsApiConfig{
		AppId:     w.appId,
		Timestamp: timestamp,
		NonceStr:  nonceStr,
		Signature: signature,
	}
}

func (w *WxOfficialHandler) CheckExpire() bool {
	now := time.Now()
	if w.accessTokenExpireAt.Before(now) && w.jsapiTicketExipreAt.Before(now) {
		return true
	}
	return false
}

// RefreshAccessTokenAndTicketToMemCache 如果有redis缓存，建议使用redis分布式缓存，单服务部署则直接使用
func (w *WxOfficialHandler) RefreshAccessTokenAndTicketToMemCache(ctx context.Context) error {
	accessTokenResp, err := w.GetAccessToken(ctx)
	if err != nil {
		return err
	}
	_, err = w.GetJsApiTicket(ctx, accessTokenResp.AccessToken)
	if err != nil {
		return err
	}
	return err
}
